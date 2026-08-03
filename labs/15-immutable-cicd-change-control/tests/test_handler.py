"""Regression + behavior tests for lab 15 (immutable CI/CD change control).

Headline regressions: the caller-supplied ``via_pipeline`` boolean previously
defeated the whole control, and substring ARN matching passed
``CodePipelineServiceRoleShadow`` and cross-account look-alike principals.
"""
from __future__ import annotations

import json

import pytest

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("15-immutable-cicd-change-control")

PIPELINE_ROLE = "arn:aws:iam::123456789012:role/CodePipelineServiceRole"


@pytest.fixture(autouse=True)
def _pipeline_env(monkeypatch):
    monkeypatch.setenv("PIPELINE_ACTOR_ROLE_ARNS", PIPELINE_ROLE)


def _invoke(event, lambda_context):
    s3, sns = FakeClient(), FakeClient()
    result = handler_mod.handler(event, lambda_context, s3_client=s3, sns_client=sns)
    return result, s3, sns


def _change(name="StopLogging", principal="arn:aws:iam::999999999999:user/attacker", **kw):
    return {"event_name": name, "event_time": "2026-08-01T00:00:00Z", "principal": principal, **kw}


def test_via_pipeline_field_ignored(lambda_context):
    """Regression: `via_pipeline: true` from the event previously produced
    PASS for StopLogging by an arbitrary attacker principal."""
    event = {"change_events": [_change(via_pipeline=True)]}
    result, _, sns = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    entry = body["change_event_results"][0]
    assert entry["via_pipeline"] is False
    assert entry["claimed_via_pipeline"] is True  # recorded for forensics only
    assert sns.calls_to("publish")


def test_shadow_role_name_not_pipeline(lambda_context):
    """Regression: substring matching passed CodePipelineServiceRoleShadow."""
    event = {"change_events": [_change(
        principal="arn:aws:iam::123456789012:role/CodePipelineServiceRoleShadow",
    )]}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"


def test_cross_account_same_role_not_pipeline(lambda_context):
    """Regression: a same-named role in a foreign account passed the check."""
    event = {"change_events": [_change(
        principal="arn:aws:sts::999999999999:assumed-role/CodePipelineServiceRole/x",
    )]}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"


def test_exact_pipeline_role_passes(lambda_context):
    event = {"change_events": [_change(
        principal=PIPELINE_ROLE, change_ticket="CHG-42",
    )]}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "PASS"


def test_assumed_role_arn_normalized(lambda_context):
    """STS assumed-role ARNs resolve to the underlying role identity."""
    event = {"change_events": [_change(
        principal="arn:aws:sts::123456789012:assumed-role/CodePipelineServiceRole/deploy-session",
        change_ticket="CHG-42",
    )]}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "PASS"


def test_pipeline_forbidden_api_without_ticket_is_violation(lambda_context):
    """The previous `if forbidden and pipeline_ok: pass` dead code now
    requires change-ticket correlation."""
    event = {"change_events": [_change(principal=PIPELINE_ROLE)]}
    result, *_ = _invoke(event, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    codes = [v["code"] for v in body["change_event_results"][0]["violations"]]
    assert "pipeline-forbidden-api-uncorrelated" in codes


def test_unset_pipeline_roles_is_config_error(lambda_context, monkeypatch):
    monkeypatch.delenv("PIPELINE_ACTOR_ROLE_ARNS")
    result, *_ = _invoke({"change_events": [_change()]}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_malformed_role_arn_env_is_config_error(lambda_context, monkeypatch):
    monkeypatch.setenv("PIPELINE_ACTOR_ROLE_ARNS", "CodePipelineServiceRole")
    result, *_ = _invoke({"change_events": [_change()]}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_dirty_commit_sha_fails(lambda_context):
    event = {"pipeline_run": {
        "pipeline_name": "p", "commit_sha": "dirty-build",
        "gates": {"iac_scan": True, "policy_as_code": True, "unit": True},
    }}
    result, *_ = _invoke(event, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert any("commit SHA" in i for i in body["pipeline_result"]["issues"])


def test_missing_gates_fail(lambda_context):
    event = {"pipeline_run": {
        "pipeline_name": "p", "commit_sha": "abc1234",
        "gates": {"unit": True},
    }}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"


def test_clean_pipeline_run_passes(lambda_context):
    event = {"pipeline_run": {
        "pipeline_name": "p", "commit_sha": "abc1234def",
        "gates": {"iac_scan": True, "policy_as_code": True, "unit": True},
        "deployed": True, "post_deploy_validation": True,
    }}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "PASS"


def test_unknown_event_keys_ignored_wrong_types_error(lambda_context):
    """Regression: ChangeEvent(**raw) raised uncaught TypeError on extra keys."""
    ok = {"change_events": [_change(principal=PIPELINE_ROLE, change_ticket="CHG-1", evil="x")]}
    result, *_ = _invoke(ok, lambda_context)
    assert result["compliance_status"] == "PASS"

    bad = {"change_events": [{"event_name": "StopLogging"}]}  # missing required fields
    result, *_ = _invoke(bad, lambda_context)
    assert result["compliance_status"] == "ERROR"


def test_empty_event_is_error(lambda_context):
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "ERROR"


def test_simulation_is_stamped(lambda_context):
    result, *_ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"


def test_evidence_written(lambda_context):
    event = {"change_events": [_change(principal=PIPELINE_ROLE, change_ticket="C-1")]}
    result, s3, _ = _invoke(event, lambda_context)
    assert s3.calls_to("put_object")
    assert json.loads(result["body"])["evidence_uri"].startswith("s3://test-evidence-bucket/")
