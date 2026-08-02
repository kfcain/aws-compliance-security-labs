"""Regression + behavior tests for lab 12 (backup/recovery RTO-RPO)."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("12-backup-recovery-rto-rpo")


def _invoke(event, lambda_context, *, fakes=None):
    fakes = fakes or {}
    s3 = fakes.get("s3") or FakeClient()
    sns = fakes.get("sns") or FakeClient()
    result = handler_mod.handler(event, lambda_context, s3_client=s3, sns_client=sns)
    return result, s3, sns


def _objective(**overrides):
    """A fully healthy mission_critical objective row; override to break it."""
    base = {
        "asset_id": "api-db",
        "asset_arn": "arn:aws:rds:us-east-1:123456789012:db:api-db",
        "criticality": "mission_critical",
        "rto_minutes": 60,
        "rpo_minutes": 15,
        "backup_frequency_minutes": 15,
        "vault_name": "main-vault",
        "vault_locked": True,
        "encrypted_with_cmk": True,
        "last_restore_test_at": (datetime.now(UTC) - timedelta(days=10)).isoformat(),
        "last_restore_duration_minutes": 42,
        "last_restore_success": True,
    }
    base.update(overrides)
    return base


def test_last_restore_success_string_false_fails(lambda_context):
    """Regression: last_restore_success was not coerced, so the JSON string
    "false" was truthy and a FAILED restore drill reported PASS."""
    event = {"objectives": [_objective(last_restore_success="false")]}
    result, _, sns = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    findings = body["failing_assets"][0]["findings"]
    assert any("restore test failed" in f for f in findings)
    assert sns.calls_to("publish"), "FAIL must alert"


def test_unreported_restore_success_fails_mission_critical(lambda_context):
    """An unrecognized value coerces to None (not reported) — mission_critical
    requires a recorded drill result, so the objective fails closed."""
    event = {"objectives": [_objective(last_restore_success="maybe")]}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert any(
        "not reported" in f for f in body["failing_assets"][0]["findings"]
    )


def test_mission_critical_naive_ts_no_crash(lambda_context):
    """Regression: a naive last_restore_test_at raised 'TypeError: can't
    subtract offset-naive and offset-aware datetimes' on the mission_critical
    staleness path. It must parse as UTC and flag the stale drill instead."""
    event = {"objectives": [_objective(last_restore_test_at="2020-01-01T00:00:00")]}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert any(
        "restore test stale" in f for f in body["failing_assets"][0]["findings"]
    )


def test_empty_objectives_config_error(lambda_context):
    """Regression: an empty objectives list silently became demo data. An empty
    backup-objective set is a config gap — fail closed, outside simulation."""
    for event in ({}, {"objectives": []}):
        result, s3, sns = _invoke(event, lambda_context)
        assert result["compliance_status"] == "CONFIG_ERROR"
        assert "no objectives supplied" in json.loads(result["body"])["error"]
        assert not s3.calls_to("put_object")


def test_malformed_objective_returns_error_status(lambda_context):
    """Regression: r["asset_id"] KeyError / int("abc") ValueError were
    unhandled. Malformed rows must yield ERROR with per-row detail."""
    event = {"objectives": [
        {"asset_arn": "arn:aws:s3:::x"},  # missing required fields
        _objective(asset_id="bad-rto", rto_minutes="abc"),
        _objective(asset_id="bad-ts", last_restore_test_at="not-a-timestamp"),
        _objective(asset_id="good"),  # well-formed row still evaluated
    ]}
    result, _, sns = _invoke(event, lambda_context)
    assert result["compliance_status"] == "ERROR"
    body = json.loads(result["body"])
    assert body["malformed_count"] == 3
    assert body["asset_count"] == 1
    assert all(e["error"] for e in body["malformed_objectives"])
    assert {e["asset_id"] for e in body["malformed_objectives"]} == {"unknown", "bad-rto", "bad-ts"}
    assert sns.calls_to("publish"), "non-PASS must alert"


def test_healthy_objectives_pass(lambda_context):
    event = {"objectives": [
        _objective(),
        _objective(asset_id="files", criticality="high",
                   asset_arn="arn:aws:s3:::files", rto_minutes=240,
                   rpo_minutes=60, backup_frequency_minutes=60),
    ]}
    result, s3, sns = _invoke(event, lambda_context)
    assert result["compliance_status"] == "PASS"
    body = json.loads(result["body"])
    assert body["data_source"] == "event"
    assert body["asset_count"] == 2
    assert body["recovery_plan_alignment"]["aligned"] is True
    assert body["evidence_uri"].startswith("s3://test-evidence-bucket/")
    assert not sns.calls_to("publish")


def test_backup_frequency_exceeding_rpo_fails(lambda_context):
    event = {"objectives": [_objective(backup_frequency_minutes=1440)]}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert any("exceeds RPO" in f for f in body["failing_assets"][0]["findings"])


def test_restore_slower_than_rto_fails(lambda_context):
    event = {"objectives": [_objective(last_restore_duration_minutes=90)]}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert any("> RTO" in f for f in body["failing_assets"][0]["findings"])


def test_vault_lock_string_false_fails(lambda_context):
    """Same strict-boolean rule for the immutability attestation: "false" must
    not count as a locked vault."""
    event = {"objectives": [_objective(vault_locked="false")]}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert any("vault lock" in f for f in body["failing_assets"][0]["findings"])


def test_simulation_is_stamped(lambda_context):
    result, *_ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    assert body["asset_count"] == 2
    assert result["compliance_status"] == "FAIL"  # demo includes a misaligned asset


def test_missing_bucket_is_config_error(lambda_context, monkeypatch):
    monkeypatch.delenv("EVIDENCE_BUCKET")
    result, *_ = _invoke({"objectives": [_objective()]}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_bad_policy_env_is_config_error(lambda_context, monkeypatch):
    monkeypatch.setenv("REQUIRE_VAULT_LOCK", "yes")  # strict: only true/false
    result, *_ = _invoke({"objectives": [_objective()]}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"
    assert "REQUIRE_VAULT_LOCK" in json.loads(result["body"])["error"]
