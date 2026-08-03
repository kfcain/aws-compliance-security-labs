"""Behavior tests for lab 09 (incident response automation readiness)."""
from __future__ import annotations

import json

import pytest
from botocore.exceptions import ClientError

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("09-incident-response-automation")


@pytest.fixture(autouse=True)
def _runbooks_env(monkeypatch):
    monkeypatch.setenv("REQUIRED_RUNBOOKS", "ir-isolate-instance,ir-snapshot-forensics")


def _ssm(statuses):
    """statuses: name -> 'Active'|'Creating'|None (None = missing)."""
    def describe_document(**kwargs):
        name = kwargs["Name"]
        status = statuses.get(name)
        if status is None:
            raise ClientError({"Error": {"Code": "InvalidDocument"}}, "DescribeDocument")
        return {"Document": {"Name": name, "Status": status, "DocumentVersion": "1"}}
    return FakeClient(responses={"describe_document": describe_document})


def _sns(confirmed="1"):
    return FakeClient(responses={"get_topic_attributes": {
        "Attributes": {"SubscriptionsConfirmed": confirmed, "SubscriptionsPending": "0"},
    }})


def _invoke(event, lambda_context, ssm=None, sns=None):
    ssm = ssm or _ssm({"ir-isolate-instance": "Active", "ir-snapshot-forensics": "Active"})
    sns = sns or _sns()
    s3 = FakeClient()
    hub = FakeClient(responses={"batch_import_findings": {"SuccessCount": 1}})
    result = handler_mod.handler(
        event, lambda_context,
        ssm_client=ssm, sns_client=sns, s3_client=s3, securityhub_client=hub,
    )
    return result, ssm, sns, s3, hub


def test_all_present_and_subscribed_passes(lambda_context):
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "PASS"


def test_missing_runbook_fails(lambda_context):
    ssm = _ssm({"ir-isolate-instance": "Active", "ir-snapshot-forensics": None})
    result, _, sns, _, hub = _invoke({}, lambda_context, ssm=ssm)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert body["runbooks_missing"] == ["ir-snapshot-forensics"]
    assert hub.calls_to("batch_import_findings") and sns.calls_to("publish")


def test_inactive_runbook_fails(lambda_context):
    ssm = _ssm({"ir-isolate-instance": "Active", "ir-snapshot-forensics": "Creating"})
    result, *_ = _invoke({}, lambda_context, ssm=ssm)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert body["runbooks_inactive"] == ["ir-snapshot-forensics"]


def test_unset_required_runbooks_is_config_error(lambda_context, monkeypatch):
    monkeypatch.delenv("REQUIRED_RUNBOOKS")
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_zero_confirmed_subscriptions_fails(lambda_context):
    result, *_ = _invoke({}, lambda_context, sns=_sns(confirmed="0"))
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert any(v["type"] == "escalation_topic" for v in body["violations"])


def test_other_client_error_is_error_status(lambda_context):
    ssm = FakeClient(responses={"describe_document": ClientError(
        {"Error": {"Code": "ThrottlingException"}}, "DescribeDocument")})
    result, *_ = _invoke({}, lambda_context, ssm=ssm)
    assert result["compliance_status"] == "ERROR"


def test_simulation_is_stamped_and_deterministic(lambda_context, monkeypatch):
    monkeypatch.delenv("REQUIRED_RUNBOOKS")  # simulation needs no config
    result, *_ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"


def test_evidence_written(lambda_context):
    result, _, _, s3, _ = _invoke({}, lambda_context)
    assert s3.calls_to("put_object")
    assert json.loads(result["body"])["evidence_uri"].startswith("s3://test-evidence-bucket/")
