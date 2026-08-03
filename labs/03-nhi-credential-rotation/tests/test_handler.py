"""Regression + behavior tests for lab 03 (NHI credential rotation)."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("03-nhi-credential-rotation")


def _invoke(event, lambda_context, *, fakes=None):
    fakes = fakes or {}
    iam = fakes.get("iam") or FakeClient(pages={"list_users": [], "list_access_keys": []})
    secretsmanager = fakes.get("secretsmanager") or FakeClient(pages={"list_secrets": []})
    s3 = fakes.get("s3") or FakeClient()
    sns = fakes.get("sns") or FakeClient()
    result = handler_mod.handler(
        event, lambda_context,
        iam_client=iam, secretsmanager_client=secretsmanager,
        s3_client=s3, sns_client=sns,
    )
    return result, iam, secretsmanager, s3, sns


def _item(**overrides):
    base = {
        "type": "iam_access_key",
        "principal": "arn:aws:iam::123456789012:user/ci-bot",
        "credential_id": "AKIAEXAMPLE000000001",
        "created_at": (datetime.now(UTC) - timedelta(days=10)).isoformat(),
        "rotation_enabled": None,
    }
    base.update(overrides)
    return base


def test_import_with_bad_env_then_invoke_yields_config_error(lambda_context, monkeypatch):
    """Regression: module-level int(os.environ.get("MAX_KEY_AGE_DAYS")) crashed
    Lambda INIT on a malformed value. The env must be read at handler time and
    surface as CONFIG_ERROR, not an unhandled ValueError."""
    monkeypatch.setenv("MAX_KEY_AGE_DAYS", "abc")
    # Re-run module top-level code (Lambda INIT) under the bad env — must not raise.
    handler_mod.__spec__.loader.exec_module(handler_mod)
    result, *_ = _invoke({"inventory": [_item()]}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"
    assert "MAX_KEY_AGE_DAYS" in json.loads(result["body"])["error"]


def test_malformed_inventory_returns_error_status(lambda_context):
    """Regression: item["created_at"] KeyError / fromisoformat ValueError were
    unhandled. Malformed rows must yield ERROR with per-item detail."""
    event = {"inventory": [
        {"type": "iam_access_key", "principal": "u1", "credential_id": "AKIA1"},  # no created_at
        _item(credential_id="AKIA2", created_at="not-a-timestamp"),
        _item(credential_id="AKIA3"),  # well-formed row still evaluated
    ]}
    result, *_ , sns = _invoke(event, lambda_context)
    assert result["compliance_status"] == "ERROR"
    body = json.loads(result["body"])
    assert body["malformed_count"] == 2
    assert body["evaluated_count"] == 1
    assert all(e["error"] for e in body["malformed_items"])
    assert sns.calls_to("publish"), "non-PASS must alert"


def test_naive_timestamp_treated_as_utc(lambda_context):
    """created_at without a timezone must be treated as UTC, not crash."""
    event = {"inventory": [_item(created_at="2020-01-01T00:00:00")]}  # naive, ancient
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert body["stale_count"] == 1


def test_stale_key_and_disabled_rotation_fail(lambda_context):
    old = (datetime.now(UTC) - timedelta(days=200)).isoformat()
    event = {"inventory": [
        _item(credential_id="AKIAOLD0000000000001", created_at=old),
        _item(type="secretsmanager", credential_id="app/db", rotation_enabled=False),
        _item(credential_id="AKIAFRESH00000000001"),
    ]}
    result, *_ , sns = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert body["data_source"] == "event"
    assert body["stale_count"] == 2
    reasons = {r for f in body["stale_credentials"] for r in f["reasons"]}
    assert any("exceeds max" in r for r in reasons)
    assert "rotation not enabled" in reasons
    assert sns.calls_to("publish"), "FAIL must alert"


def test_rotation_enabled_string_false_is_stale(lambda_context):
    """JSON string "false" must be treated as rotation disabled, not truthy."""
    event = {"inventory": [_item(type="secretsmanager", rotation_enabled="false")]}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"


def test_clean_event_inventory_passes(lambda_context):
    result, _, _, s3, sns = _invoke({"inventory": [_item()]}, lambda_context)
    assert result["compliance_status"] == "PASS"
    body = json.loads(result["body"])
    assert body["data_source"] == "event"
    assert body["stale_count"] == 0
    assert body["policy_max_key_age_days"] == 90
    assert not sns.calls_to("publish")
    assert s3.calls_to("put_object"), "evidence must be persisted"


def test_live_discovery_paginates_iam_and_secrets(lambda_context):
    """Empty event → real discovery: list_users + list_access_keys per user and
    list_secrets, all paginated, stamped data_source=aws-api."""
    now = datetime.now(UTC)
    iam = FakeClient(pages={
        "list_users": [
            {"Users": [{"UserName": "ci-bot", "Arn": "arn:aws:iam::123456789012:user/ci-bot"}]},
            {"Users": [{"UserName": "deploy", "Arn": "arn:aws:iam::123456789012:user/deploy"}]},
        ],
        "list_access_keys": [
            {"AccessKeyMetadata": [
                {"AccessKeyId": "AKIAOLD0000000000001", "Status": "Active",
                 "CreateDate": now - timedelta(days=200)},
            ]},
        ],
    })
    secretsmanager = FakeClient(pages={
        "list_secrets": [
            {"SecretList": [{
                "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds",
                "Name": "db-creds", "RotationEnabled": True,
                "LastRotatedDate": now - timedelta(days=5),
            }]},
            {"SecretList": [{
                "Name": "api-token-config", "RotationEnabled": False,
                "CreatedDate": now - timedelta(days=10),
            }]},
        ],
    })
    result, *_ = _invoke({}, lambda_context, fakes={"iam": iam, "secretsmanager": secretsmanager})
    body = json.loads(result["body"])
    assert body["data_source"] == "aws-api"
    # 2 users x 1 key page (both stale by age) + 2 secrets (1 rotation disabled)
    assert body["inventory_count"] == 4
    assert body["inventory_by_type"] == {"iam_access_key": 2, "secretsmanager": 2}
    assert body["stale_count"] == 3
    assert result["compliance_status"] == "FAIL"


def test_empty_event_inventory_triggers_live_discovery(lambda_context):
    result, *_ = _invoke({"inventory": []}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "aws-api"


def test_no_demo_data_outside_simulation(lambda_context):
    """An empty live sweep is a clean PASS with zero credentials — never demo rows."""
    result, *_ = _invoke({}, lambda_context)
    body = json.loads(result["body"])
    assert body["inventory_count"] == 0
    assert body["data_source"] == "aws-api"
    assert result["compliance_status"] == "PASS"


def test_simulation_is_stamped(lambda_context):
    result, *_ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    assert body["inventory_count"] == 2
    assert result["compliance_status"] == "FAIL"  # demo includes one stale key


def test_evidence_written_to_bucket(lambda_context):
    result, *_ , s3, _ = _invoke({"inventory": [_item()]}, lambda_context)
    put = s3.calls_to("put_object")
    assert put and put[0]["Bucket"] == "test-evidence-bucket"
    assert json.loads(result["body"])["evidence_uri"].startswith("s3://test-evidence-bucket/")


def test_missing_bucket_is_config_error(lambda_context, monkeypatch):
    monkeypatch.delenv("EVIDENCE_BUCKET")
    result, *_ = _invoke({"inventory": [_item()]}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_sdk_error_is_error_status(lambda_context):
    boom = FakeClient()  # no pages configured → get_paginator raises ValueError
    result, *_ = _invoke({}, lambda_context, fakes={"iam": boom})
    assert result["compliance_status"] == "ERROR"


def test_custom_max_age_env_applies(lambda_context, monkeypatch):
    monkeypatch.setenv("MAX_KEY_AGE_DAYS", "5")
    event = {"inventory": [_item()]}  # 10 days old — stale under the 5-day policy
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"
    assert json.loads(result["body"])["policy_max_key_age_days"] == 5
