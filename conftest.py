"""Shared pytest harness for all 15 lab handler suites.

Loads handlers by file path (the labs all name their module ``handler.py``)
and provides hand-rolled boto3 client fakes so every test runs offline with
no credentials.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parent

DEFAULT_TEST_ARN = "arn:aws:lambda:us-east-1:123456789012:function:lab-test"
GOVCLOUD_TEST_ARN = "arn:aws-us-gov:lambda:us-gov-west-1:123456789012:function:lab-test"


def load_lab_module(lab_id: str, module: str = "handler"):
    """Import ``labs/<lab_id>/src/<module>.py`` under a unique module name.

    The lab's ``src`` dir is put on sys.path so the handler's
    ``import lab_common`` resolves to its vendored copy (all copies are
    byte-identical — enforced by scripts/check-common-sync.mjs).
    """
    src_dir = ROOT / "labs" / lab_id / "src"
    path = src_dir / f"{module}.py"
    if not path.exists():
        raise FileNotFoundError(path)
    unique_name = f"{lab_id.replace('-', '_')}__{module}"
    if unique_name in sys.modules:
        return sys.modules[unique_name]
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    spec = importlib.util.spec_from_file_location(unique_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = mod
    spec.loader.exec_module(mod)
    return mod


class FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]):
        self._pages = pages

    def paginate(self, **_kwargs):
        yield from self._pages


class _SequencedPages:
    """Wraps a list of page-sets: each get_paginator().paginate() run consumes
    the next page-set (the last one repeats). Configure by passing a list of
    LISTS as a `pages` value."""

    def __init__(self, page_sets: list[list[dict[str, Any]]]):
        self._sets = list(page_sets)

    def next_set(self) -> list[dict[str, Any]]:
        if len(self._sets) > 1:
            return self._sets.pop(0)
        return self._sets[0]


class FakeClient:
    """Recorder-style boto3 client fake.

    ``responses`` maps method name -> canned response. Values may be:
      * a dict — returned on every call
      * a list of dicts — consumed one per call (last one repeats)
      * a callable — invoked with the call kwargs
      * an Exception instance — raised
    Paginated APIs are configured via ``pages`` (method name -> list of pages).
    Every call is recorded in ``calls`` as (method, kwargs).
    """

    def __init__(
        self,
        responses: dict[str, Any] | None = None,
        pages: dict[str, list[dict[str, Any]]] | None = None,
    ):
        self.responses = responses or {}
        self.pages = pages or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def can_paginate(self, operation_name: str) -> bool:
        return operation_name in self.pages

    def get_paginator(self, operation_name: str) -> FakePaginator:
        if operation_name not in self.pages:
            raise ValueError(f"no fake pages configured for {operation_name}")
        configured = self.pages[operation_name]
        if isinstance(configured, _SequencedPages):
            return FakePaginator(configured.next_set())
        if configured and isinstance(configured[0], list):
            wrapped = _SequencedPages(configured)
            self.pages[operation_name] = wrapped
            return FakePaginator(wrapped.next_set())
        return FakePaginator(configured)

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)

        def method(**kwargs):
            self.calls.append((name, kwargs))
            response = self.responses.get(name, {})
            if isinstance(response, Exception):
                raise response
            if callable(response):
                return response(**kwargs)
            if isinstance(response, list):
                if not response:
                    raise AssertionError(f"fake {name} exhausted its canned responses")
                return response.pop(0) if len(response) > 1 else response[0]
            return response

        return method

    def calls_to(self, name: str) -> list[dict[str, Any]]:
        return [kwargs for method, kwargs in self.calls if method == name]


class FakeLambdaContext:
    def __init__(
        self,
        arn: str = DEFAULT_TEST_ARN,
        request_id: str = "test-request-id",
        remaining_ms: int = 60_000,
    ):
        self.invoked_function_arn = arn
        self.aws_request_id = request_id
        self._remaining_ms = remaining_ms

    def get_remaining_time_in_millis(self) -> int:
        return self._remaining_ms


@pytest.fixture
def lambda_context() -> FakeLambdaContext:
    return FakeLambdaContext()


@pytest.fixture
def govcloud_context() -> FakeLambdaContext:
    return FakeLambdaContext(arn=GOVCLOUD_TEST_ARN)


@pytest.fixture
def fake_s3() -> FakeClient:
    return FakeClient()


@pytest.fixture
def fake_sns() -> FakeClient:
    return FakeClient()


@pytest.fixture
def fake_securityhub() -> FakeClient:
    return FakeClient(responses={"batch_import_findings": {"SuccessCount": 1, "FailedCount": 0}})


@pytest.fixture(autouse=True)
def _lab_env(monkeypatch):
    """Baseline env for every test: evidence bucket + topic set, no leakage
    from the host environment. Individual tests override/delete as needed."""
    monkeypatch.setenv("EVIDENCE_BUCKET", "test-evidence-bucket")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:test-alerts")
    monkeypatch.delenv("LAB_RUNTIME_ARN", raising=False)
