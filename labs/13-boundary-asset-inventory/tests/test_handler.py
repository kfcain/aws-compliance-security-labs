"""Regression + behavior tests for lab 13 (boundary asset inventory)."""
from __future__ import annotations

import json

import pytest

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("13-boundary-asset-inventory")

BOUNDARY = {
    "system_name": "Federal SaaS CSO",
    "mas_version": "2026.1",
    "in_scope_account_ids": ["111111111111"],
    "in_scope_services": ["AWS::S3::Bucket"],
}


def _item(account="111111111111", **overrides):
    base = {
        "resource_id": "arn:aws:s3:::cso-tenant-data",
        "resource_type": "AWS::S3::Bucket",
        "account_id": account,
        "region": "us-gov-west-1",
        "tags": {
            "boundary_status": "in_boundary",
            "federal_tenant_id": "agency-a",
            "data_classification": "CUI",
            "owner": "platform-team",
        },
        "processes_federal_data": True,
    }
    base.update(overrides)
    return base


@pytest.fixture(autouse=True)
def _lab13_env(monkeypatch):
    monkeypatch.delenv("ALLOWED_ACCOUNT_IDS", raising=False)
    monkeypatch.delenv("REQUIRED_TAGS", raising=False)


def _invoke(event, lambda_context, *, fakes=None):
    fakes = fakes or {}
    s3 = fakes.get("s3") or FakeClient()
    sns = fakes.get("sns") or FakeClient()
    result = handler_mod.handler(event, lambda_context, s3_client=s3, sns_client=sns)
    return result, s3, sns


def test_unknown_boundary_keys_ignored(lambda_context):
    """Regression: `BoundaryDefinition(**braw)` raised an uncaught TypeError
    on any extra key. Unknown keys (boundary and inventory item) are ignored."""
    event = {
        "boundary": {**BOUNDARY, "reviewed_by": "iso", "extra": {"nested": True}},
        "inventory": [_item(unexpected_key="ignored")],
    }
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "PASS"
    body = json.loads(result["body"])
    assert body["boundary"]["system_name"] == "Federal SaaS CSO"
    assert body["inventory_count"] == 1


def test_string_account_ids_rejected(lambda_context):
    """Regression: a string passed as in_scope_account_ids silently became a
    set of characters, so no real account could ever match. Now: ERROR."""
    event = {
        "boundary": {**BOUNDARY, "in_scope_account_ids": "111111111111"},
        "inventory": [_item()],
    }
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "ERROR"
    assert "in_scope_account_ids" in json.loads(result["body"])["error"]


def test_no_default_accounts_config_error(lambda_context):
    """Regression: ALLOWED_ACCOUNTS defaulted to two placeholder accounts, so
    an unconfigured deploy still classified them in-boundary. Now: no boundary
    in the event and no ALLOWED_ACCOUNT_IDS → CONFIG_ERROR."""
    result, *_ = _invoke({"inventory": [_item()]}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"
    assert "boundary" in json.loads(result["body"])["error"]


def test_event_can_narrow_boundary(lambda_context, monkeypatch):
    """Regression: the env account list was unioned into every boundary, so an
    event could never narrow scope. The event boundary is now authoritative."""
    monkeypatch.setenv("ALLOWED_ACCOUNT_IDS", "111111111111,222222222222")
    event = {
        "boundary": BOUNDARY,  # narrows to 111111111111 only
        "inventory": [_item(account="222222222222")],
    }
    result, _, sns = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert body["boundary_source"] == "event"
    assert body["counts_by_classification"]["out_of_boundary"] == 1
    assert len(body["federal_data_outside_boundary"]) == 1
    assert sns.calls_to("publish"), "FAIL must alert"


def test_env_baseline_when_event_omits_boundary(lambda_context, monkeypatch):
    monkeypatch.setenv("ALLOWED_ACCOUNT_IDS", "111111111111")
    result, *_ = _invoke({"inventory": [_item()]}, lambda_context)
    assert result["compliance_status"] == "PASS"
    body = json.loads(result["body"])
    assert body["boundary_source"] == "env"
    assert body["counts_by_classification"]["in_boundary"] == 1


def test_empty_inventory_config_error(lambda_context):
    """Regression: an empty inventory list silently fell back to demo data.
    The lab attests a live feed — an empty feed is CONFIG_ERROR, never a
    PASS over demo assets."""
    result, *_ = _invoke({"boundary": BOUNDARY, "inventory": []}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"
    assert "inventory" in json.loads(result["body"])["error"]


def test_missing_resource_id_is_error(lambda_context):
    """Regression: `i["resource_id"]` raised an unhandled KeyError."""
    event = {
        "boundary": BOUNDARY,
        "inventory": [{"resource_type": "AWS::S3::Bucket", "account_id": "111111111111"}],
    }
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "ERROR"
    assert "resource_id" in json.loads(result["body"])["error"]


def test_simulation_is_stamped(lambda_context):
    result, s3, sns = _invoke({"mode": "simulation"}, lambda_context)
    assert result["compliance_status"] == "FAIL"  # demo shadow-analytics bucket
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    assert body["boundary_source"] == "simulation"
    assert len(body["federal_data_outside_boundary"]) == 1
    assert body["evidence_uri"].startswith("s3://test-evidence-bucket/")
    assert s3.calls_to("put_object")
    assert sns.calls_to("publish")


def test_only_governance_tags_in_evidence(lambda_context):
    """Full tag maps are not echoed — only the governance tags the
    classification logic reads (REQUIRED_TAGS + boundary_status)."""
    item = _item()
    item["tags"]["internal_note"] = "contains raw PII dump locations"
    result, *_ = _invoke({"boundary": BOUNDARY, "inventory": [item]}, lambda_context)
    assert result["compliance_status"] == "PASS"
    body = json.loads(result["body"])
    assert "internal_note" not in result["body"]
    tags = body["results"][0]["governance_tags"]
    assert tags["boundary_status"] == "in_boundary"
    assert tags["data_classification"] == "CUI"


def test_non_namespaced_type_skips_catalog_check(lambda_context):
    """Regression: `resource_type.split("::")[0:2]` was always truthy, so the
    MAS-catalog warning fired for free-form type strings. Only well-formed
    AWS::Service::Resource types are compared against the catalog."""
    item = _item(resource_type="CustomInventoryRecord")
    result, *_ = _invoke({"boundary": BOUNDARY, "inventory": [item]}, lambda_context)
    assert result["compliance_status"] == "PASS"
    body = json.loads(result["body"])
    assert body["results"][0]["issues"] == []


def test_namespaced_type_outside_catalog_flagged(lambda_context):
    item = _item(
        resource_id="arn:aws:dynamodb:us-gov-west-1:111111111111:table/t",
        resource_type="AWS::DynamoDB::Table",
    )
    result, *_ = _invoke({"boundary": BOUNDARY, "inventory": [item]}, lambda_context)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert any("MAS service catalog" in i for i in body["results"][0]["issues"])


def test_federal_data_missing_tags_fails(lambda_context):
    item = _item(tags={"boundary_status": "in_boundary"})
    result, *_ = _invoke({"boundary": BOUNDARY, "inventory": [item]}, lambda_context)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert any("missing tags" in i for i in body["results"][0]["issues"])


def test_missing_bucket_is_config_error(lambda_context, monkeypatch):
    monkeypatch.delenv("EVIDENCE_BUCKET")
    result, *_ = _invoke({"boundary": BOUNDARY, "inventory": [_item()]}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"
