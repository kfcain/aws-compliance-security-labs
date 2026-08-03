"""Behavior tests for lab 05 (GuardDuty threat detection & response)."""
from __future__ import annotations

import json

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("05-guardduty-automated-response")


def _guardduty(detectors=("det-1",), status="ENABLED", finding_ids=None, findings=None):
    return FakeClient(
        pages={
            "list_detectors": [{"DetectorIds": list(detectors)}],
            "list_findings": [{"FindingIds": finding_ids or []}],
        },
        responses={
            "get_detector": {"Status": status, "FindingPublishingFrequency": "FIFTEEN_MINUTES"},
            "get_findings": {"Findings": findings or []},
        },
    )


def _invoke(event, lambda_context, gd=None):
    gd = gd or _guardduty()
    s3, sns = FakeClient(), FakeClient()
    hub = FakeClient(responses={"batch_import_findings": {"SuccessCount": 1}})
    result = handler_mod.handler(
        event, lambda_context,
        guardduty_client=gd, s3_client=s3, sns_client=sns, securityhub_client=hub,
    )
    return result, gd, s3, sns, hub


def test_no_detector_is_config_error(lambda_context):
    gd = _guardduty(detectors=())
    result, *_ = _invoke({}, lambda_context, gd)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_disabled_detector_fails(lambda_context):
    gd = _guardduty(status="DISABLED")
    result, _, _, sns, _ = _invoke({}, lambda_context, gd)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert "disabled" in body["detector_violations"][0]
    assert sns.calls_to("publish")


def test_high_severity_finding_fails_with_asff(lambda_context):
    gd = _guardduty(
        finding_ids=["f-1"],
        findings=[{
            "Id": "f-1", "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
            "Severity": 8.0, "Title": "SSH brute force",
            "UpdatedAt": "2026-08-01T00:00:00Z",
            "Resource": {"ResourceType": "Instance"},
        }],
    )
    result, _, _, sns, hub = _invoke({}, lambda_context, gd)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert body["finding_count"] == 1
    assert body["findings_by_band"] == {"high": 1}
    assert hub.calls_to("batch_import_findings") and sns.calls_to("publish")


def test_clean_detector_passes(lambda_context):
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "PASS"


def test_get_findings_chunked_at_50(lambda_context):
    ids = [f"f-{i}" for i in range(120)]
    gd = _guardduty(finding_ids=ids, findings=[])
    _invoke({}, lambda_context, gd)
    chunks = [len(c["FindingIds"]) for c in gd.calls_to("get_findings")]
    assert chunks == [50, 50, 20]


def test_bad_threshold_env_is_config_error(lambda_context, monkeypatch):
    monkeypatch.setenv("SEVERITY_THRESHOLD", "high")
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_simulation_is_stamped_and_fails(lambda_context):
    result, *_ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    assert result["compliance_status"] == "FAIL"


def test_sdk_error_is_error_status(lambda_context):
    result, *_ = _invoke({}, lambda_context, FakeClient())  # no pages configured
    assert result["compliance_status"] == "ERROR"


def test_evidence_written(lambda_context):
    result, _, s3, *_ = _invoke({}, lambda_context)
    assert s3.calls_to("put_object")
    assert json.loads(result["body"])["evidence_uri"].startswith("s3://test-evidence-bucket/")
