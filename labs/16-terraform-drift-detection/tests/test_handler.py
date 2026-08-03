"""Behavior tests for lab 16 (Terraform state drift detection)."""
from __future__ import annotations

import io
import json

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("16-terraform-drift-detection")


def _drift(address, actions=("update",), before=None, after=None, rtype=None):
    return {
        "address": address,
        "type": rtype or address.split(".", 1)[0],
        "change": {"actions": list(actions), "before": before or {}, "after": after or {}},
    }


def _plan(*drifts):
    return {"format_version": "1.2", "resource_drift": list(drifts)}


def _invoke(event, lambda_context, s3=None):
    s3, sns = s3 or FakeClient(), FakeClient()
    hub = FakeClient(responses={"batch_import_findings": {"SuccessCount": 1}})
    result = handler_mod.handler(
        event, lambda_context, s3_client=s3, sns_client=sns, securityhub_client=hub,
    )
    return result, s3, sns, hub


def test_security_group_ingress_is_critical_and_fails(lambda_context):
    plan = _plan(_drift(
        "aws_security_group.web.ingress",
        before={"ingress": ["10.0.0.0/8"]}, after={"ingress": ["0.0.0.0/0"]},
    ))
    result, _, sns, hub = _invoke({"plan": plan}, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert body["drift_by_severity"].get("critical") == 1
    assert hub.calls_to("batch_import_findings") and sns.calls_to("publish")


def test_tag_only_drift_is_low_and_passes_at_default_threshold(lambda_context):
    plan = _plan(_drift(
        "aws_instance.app",
        before={"tags": {"env": "prod"}},
        after={"tags": {"env": "prod", "owner": "x"}},
    ))
    result, *_ = _invoke({"plan": plan}, lambda_context)
    body = json.loads(result["body"])
    # low severity is below the default FAIL_SEVERITY=high
    assert result["compliance_status"] == "PASS"
    assert body["drifted_resource_count"] == 1
    assert body["actionable_drift_count"] == 0


def test_delete_action_is_high_and_fails(lambda_context):
    plan = _plan(_drift("aws_s3_bucket.logs", actions=["delete"]))
    result, *_ = _invoke({"plan": plan}, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert body["drift_by_severity"].get("high") == 1


def test_lower_threshold_makes_low_drift_actionable(lambda_context, monkeypatch):
    monkeypatch.setenv("FAIL_SEVERITY", "low")
    plan = _plan(_drift(
        "aws_instance.app", before={"tags": {}}, after={"tags": {"a": "b"}},
    ))
    result, *_ = _invoke({"plan": plan}, lambda_context)
    assert result["compliance_status"] == "FAIL"


def test_ignore_pattern_marks_expected_drift(lambda_context, monkeypatch):
    monkeypatch.setenv("DRIFT_IGNORE", "aws_autoscaling_group.*.desired_capacity")
    plan = _plan(_drift(
        "aws_autoscaling_group.workers",
        before={"desired_capacity": 3}, after={"desired_capacity": 5},
    ))
    result, *_ = _invoke({"plan": plan}, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "PASS"
    assert body["ignored_count"] == 1
    assert body["drifted_resource_count"] == 0


def test_no_drift_passes(lambda_context):
    result, *_ = _invoke({"plan": _plan()}, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "PASS"
    assert body["drifted_resource_count"] == 0


def test_resource_changes_fallback_when_no_resource_drift(lambda_context):
    plan = {
        "format_version": "1.1",
        "resource_changes": [
            {"address": "aws_iam_policy.admin", "type": "aws_iam_policy",
             "change": {"actions": ["update"], "before": {"policy": "a"}, "after": {"policy": "b"}}},
            {"address": "aws_instance.stable", "type": "aws_instance",
             "change": {"actions": ["no-op"]}},
        ],
    }
    result, *_ = _invoke({"plan": plan}, lambda_context)
    body = json.loads(result["body"])
    # only the non-no-op iam_policy counts, and it is critical
    assert body["drifted_resource_count"] == 1
    assert body["drift_by_severity"].get("critical") == 1
    assert result["compliance_status"] == "FAIL"


def test_plan_read_from_s3(lambda_context, monkeypatch):
    monkeypatch.setenv("PLAN_BUCKET", "tfplans")
    monkeypatch.setenv("PLAN_KEY", "prod/plan.json")
    plan = _plan(_drift("aws_kms_key.data", after={"policy": "*"}))
    s3 = FakeClient(responses={"get_object": {"Body": io.BytesIO(json.dumps(plan).encode())}})
    result, s3, *_ = _invoke({}, lambda_context, s3=s3)
    body = json.loads(result["body"])
    assert body["data_source"] == "s3"
    assert s3.calls_to("get_object")[0]["Key"] == "prod/plan.json"
    assert result["compliance_status"] == "FAIL"


def test_no_plan_is_config_error(lambda_context):
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_bad_fail_severity_is_config_error(lambda_context, monkeypatch):
    monkeypatch.setenv("FAIL_SEVERITY", "catastrophic")
    result, *_ = _invoke({"plan": _plan()}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_malformed_drift_entry_is_error(lambda_context):
    result, *_ = _invoke({"plan": {"resource_drift": ["not-an-object"]}}, lambda_context)
    assert result["compliance_status"] == "ERROR"


def test_simulation_is_stamped_and_fails(lambda_context):
    result, *_ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    # sim plan has a critical SG-ingress drift and an ignored-less autoscaling drift
    assert result["compliance_status"] == "FAIL"
    assert body["drift_by_severity"].get("critical") == 1


def test_evidence_written(lambda_context):
    result, s3, *_ = _invoke({"mode": "simulation"}, lambda_context)
    assert s3.calls_to("put_object")
    assert json.loads(result["body"])["evidence_uri"].startswith("s3://test-evidence-bucket/")


def test_classify_severity_matrix():
    assert handler_mod.classify_severity("aws_security_group.web", ["update"], "ingress") == "critical"
    assert handler_mod.classify_severity("aws_iam_policy.admin", ["update"], "policy") == "critical"
    assert handler_mod.classify_severity("aws_instance.app", ["update"], "instance_type") == "high"
    assert handler_mod.classify_severity("aws_s3_bucket.x", ["delete"], None) == "high"
    assert handler_mod.classify_severity("aws_instance.app", ["update"], "tags") == "low"
    assert handler_mod.classify_severity("random_pet.name", ["update"], "length") == "medium"
