"""Regression + behavior tests for lab 02 (Inspector VDR)."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("02-inspector-vdr")


def _invoke(event, lambda_context, *, pages=None, fakes=None):
    fakes = fakes or {}
    securityhub = fakes.get("securityhub") or FakeClient(pages=pages or {"get_findings": []})
    s3 = fakes.get("s3") or FakeClient()
    sns = fakes.get("sns") or FakeClient()
    result = handler_mod.handler(
        event, lambda_context,
        securityhub_client=securityhub, s3_client=s3, sns_client=sns,
    )
    return result, securityhub, s3, sns


def test_naive_timestamp_treated_as_utc(lambda_context):
    """Regression: FirstObservedAt without a timezone raised
    'TypeError: can't compare offset-naive and offset-aware datetimes'."""
    event = {"findings": [{
        "Id": "f1", "Title": "t", "Severity": {"Label": "HIGH"},
        "FirstObservedAt": "2020-01-01T00:00:00",  # naive, long past SLA
        "Resources": [{"Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-1"}],
    }]}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert body["sla_breaches"] == 1


def test_all_findings_reported_with_counts(lambda_context):
    """Regression: breached_findings was silently truncated to 50 while
    sla_breaches reported the true count."""
    old = (datetime.now(UTC) - timedelta(days=400)).isoformat()
    event = {"findings": [
        {"Id": f"f{i}", "Severity": {"Label": "CRITICAL"}, "FirstObservedAt": old}
        for i in range(60)
    ]}
    result, *_ = _invoke(event, lambda_context)
    body = json.loads(result["body"])
    assert body["sla_breaches"] == 60
    assert len(body["breached_findings"]) == 60


def test_scheduled_sweep_pulls_paginated_findings(lambda_context):
    old = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    pages = {"get_findings": [
        {"Findings": [{"Id": "a", "Severity": {"Label": "HIGH"}, "FirstObservedAt": old}]},
        {"Findings": [{"Id": "b", "Severity": {"Label": "LOW"}, "FirstObservedAt": old}]},
    ]}
    result, securityhub, s3, sns = _invoke({}, lambda_context, pages=pages)
    body = json.loads(result["body"])
    assert body["open_findings"] == 2
    assert body["data_source"] == "securityhub"
    # HIGH at 30 days is breached (7-day SLA); LOW is not (90-day SLA)
    assert body["sla_breaches"] == 1
    assert result["compliance_status"] == "FAIL"
    assert sns.calls_to("publish"), "FAIL must alert"


def test_no_demo_data_outside_simulation(lambda_context):
    """An empty sweep is a clean PASS with zero findings — never demo data."""
    result, *_ = _invoke({}, lambda_context)
    body = json.loads(result["body"])
    assert body["open_findings"] == 0
    assert body["data_source"] == "securityhub"


def test_simulation_is_stamped(lambda_context):
    result, *_ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    assert body["open_findings"] == 1


def test_evidence_written_to_bucket(lambda_context):
    s3 = FakeClient()
    result, _, s3, _ = _invoke({}, lambda_context, fakes={"s3": s3})
    put = s3.calls_to("put_object")
    assert put and put[0]["Bucket"] == "test-evidence-bucket"
    assert json.loads(result["body"])["evidence_uri"].startswith("s3://test-evidence-bucket/")


def test_missing_bucket_is_config_error(lambda_context, monkeypatch):
    monkeypatch.delenv("EVIDENCE_BUCKET")
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_sdk_error_is_error_status(lambda_context):
    boom = FakeClient()
    boom.pages = {}  # get_paginator will raise ValueError
    result, *_ = _invoke({}, lambda_context, fakes={"securityhub": boom})
    assert result["compliance_status"] == "ERROR"


def test_severity_classification_matrix():
    assert handler_mod.classify("CRITICAL") == "N1"
    assert handler_mod.classify("informational") == "N5"
    assert handler_mod.classify("unknown") == "N3"
