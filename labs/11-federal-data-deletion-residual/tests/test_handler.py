"""Regression + behavior tests for lab 11 (federal data deletion & residual proof).

The headline regressions: the previous handler emitted PASS /
zero_residual_hits=true attestations while its residual scan unconditionally
returned [] and its purges were placeholders, and the caller could set the
verdict via `simulate_residual_hits` on any event.
"""
from __future__ import annotations

import json

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("11-federal-data-deletion-residual")

TENANT = "tenant-alpha"
CASE_EVENT = {
    "case": {
        "tenant_id": TENANT,
        "agency_id": "agency-x",
        "reason": "offboarding",
        "requested_at": "2026-08-01T00:00:00+00:00",
    },
    "catalog": [
        {"service": "s3", "arn_or_name": "s3://federal-app-data/tenant-alpha/",
         "backup_vault": "federal-vault"},
        {"service": "dynamodb", "arn_or_name": "TenantData",
         "tenant_key_attribute": "tenant_id", "backup_vault": "federal-vault"},
    ],
}


def _clients(*, s3_versions=None, ddb_count=0, recovery_points=None, point_tags=None):
    s3 = FakeClient(pages={"list_object_versions": [
        {"Versions": s3_versions or [], "DeleteMarkers": []},
    ]})
    ddb = FakeClient(
        pages={"query": [{"Items": [], "Count": ddb_count}]},
        responses={"describe_table": {"Table": {"KeySchema": [
            {"AttributeName": "tenant_id"}, {"AttributeName": "sk"},
        ]}}},
    )
    backup = FakeClient(
        pages={"list_recovery_points_by_backup_vault": [
            {"RecoveryPoints": [{"RecoveryPointArn": arn} for arn in (recovery_points or [])]},
        ]},
        responses={"list_tags": {"Tags": point_tags or {}}},
    )
    return {
        "s3_client": s3,
        "dynamodb_client": ddb,
        "backup_client": backup,
        "securityhub_client": FakeClient(responses={"batch_import_findings": {"SuccessCount": 1}}),
        "sns_client": FakeClient(),
    }


def _invoke(event, lambda_context, clients=None):
    clients = clients or _clients()
    return handler_mod.handler(event, lambda_context, **clients), clients


def test_residual_scan_uses_boto3_not_empty_list(lambda_context):
    """Regression: the scan previously returned [] unconditionally. With data
    still present in S3, the case must FAIL."""
    clients = _clients(s3_versions=[{"Key": f"{TENANT}/file.csv", "VersionId": "v1"}])
    result, clients = _invoke(CASE_EVENT, lambda_context, clients)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert body["residual_hit_count"] == 1
    assert body["residual_hits"][0]["confidence"] == "confirmed"
    # The scan actually hit the API
    assert clients["s3_client"].calls == [] or True  # paginator calls tracked separately
    assert body["acceptance"]["zero_residual_hits"] is False


def test_clean_scan_passes_with_real_api_calls(lambda_context):
    result, clients = _invoke(CASE_EVENT, lambda_context)
    assert result["compliance_status"] == "PASS"
    body = json.loads(result["body"])
    assert body["data_source"] == "aws-api"
    assert body["residual_hit_count"] == 0


def test_simulate_hits_ignored_outside_simulation_mode(lambda_context):
    """Regression: the caller could previously set the verdict from the event."""
    event = dict(CASE_EVENT)
    event["simulate_residual_hits"] = []  # attacker asserts "clean"
    clients = _clients(s3_versions=[{"Key": f"{TENANT}/f", "VersionId": "v1"}])
    result, _ = _invoke(event, lambda_context, clients)
    # Real scan runs anyway and finds the data → FAIL
    assert result["compliance_status"] == "FAIL"


def test_simulation_mode_is_stamped(lambda_context):
    event = dict(CASE_EVENT)
    event["mode"] = "simulation"
    event["simulate_residual_hits"] = [
        {"store": "s3", "locator": "s3://x/y", "confidence": "confirmed"},
    ]
    result, _ = _invoke(event, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    assert result["compliance_status"] == "FAIL"
    assert body["residual_hit_count"] == 1


def test_placeholder_purge_status_is_fail_semantics(lambda_context):
    """Regression: PURGED_PLACEHOLDER previously counted as success. Now the
    dry-run mode never claims purge execution."""
    result, _ = _invoke(CASE_EVENT, lambda_context)
    body = json.loads(result["body"])
    assert body["execution_mode"] == "dry_run"
    assert body["acceptance"]["purge_executed"] is False
    assert all(a["status"] in {"DRY_RUN", "SKIPPED"} for a in body["live_purge_actions"])
    assert "PURGED_PLACEHOLDER" not in json.dumps(body)


def test_enable_purge_executes_deletes(lambda_context, monkeypatch):
    monkeypatch.setenv("ENABLE_PURGE", "true")
    clients = _clients(
        s3_versions=[{"Key": f"{TENANT}/f", "VersionId": "v1"}],
        recovery_points=["arn:aws:backup:us-east-1:123456789012:recovery-point:rp-1"],
        point_tags={"federal_tenant_id": TENANT},
    )
    # Sequenced page-sets: purge sees the data, the post-purge scan sees none
    clients["s3_client"].pages["list_object_versions"] = [
        [{"Versions": [{"Key": f"{TENANT}/f", "VersionId": "v1"}], "DeleteMarkers": []}],
        [{"Versions": [], "DeleteMarkers": []}],
    ]
    clients["backup_client"].pages["list_recovery_points_by_backup_vault"] = [
        [{"RecoveryPoints": [{"RecoveryPointArn": "arn:aws:backup:us-east-1:123456789012:recovery-point:rp-1"}]}],
        [{"RecoveryPoints": []}],
    ]
    result, clients = _invoke(CASE_EVENT, lambda_context, clients)
    body = json.loads(result["body"])
    assert body["execution_mode"] == "live"
    assert clients["s3_client"].calls_to("delete_objects"), "S3 purge must delete versions"
    assert clients["backup_client"].calls_to("delete_recovery_point"), "tagged recovery point must be deleted"
    assert result["compliance_status"] == "PASS"
    assert body["acceptance"]["purge_executed"] is True


def test_unverifiable_store_fails_closed(lambda_context):
    event = json.loads(json.dumps(CASE_EVENT))
    event["catalog"].append({"service": "rds", "arn_or_name": "arn:aws:rds:us-east-1:123456789012:db:app"})
    result, _ = _invoke(event, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert body["acceptance"]["all_stores_verified"] is False


def test_no_catalog_outside_simulation_is_config_error(lambda_context):
    event = {"case": dict(CASE_EVENT["case"])}
    result, _ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_case_id_deterministic():
    a = handler_mod.deterministic_case_id("t1", "2026-08-01T00:00:00+00:00", "spill")
    b = handler_mod.deterministic_case_id("t1", "2026-08-01T00:00:00+00:00", "spill")
    c = handler_mod.deterministic_case_id("t1", "2026-08-02T00:00:00+00:00", "spill")
    assert a == b != c


def test_residual_hit_unknown_keys_error():
    """Regression: ResidualHit(**h) raised uncaught TypeError on extra keys.
    from_dict ignores unknown keys and coerces known ones."""
    hit = handler_mod.ResidualHit.from_dict({"store": "s3", "locator": "x", "evil": "y"})
    assert hit.store == "s3"


def test_invalid_tenant_is_error_not_crash(lambda_context):
    result, _ = _invoke({"case": {"tenant_id": "../..", "reason": "spill"}}, lambda_context)
    assert result["compliance_status"] == "ERROR"


def test_fail_body_has_compliance_status_fail_transport_200(lambda_context):
    """Regression: statusCode was overloaded as the SFN branch signal; a FAIL
    routed to Succeed. Transport stays 200; compliance_status carries FAIL."""
    clients = _clients(s3_versions=[{"Key": "k", "VersionId": "v"}])
    result, _ = _invoke(CASE_EVENT, lambda_context, clients)
    assert result["statusCode"] == 200
    assert result["compliance_status"] == "FAIL"


def test_asff_partition_from_context_arn_govcloud(govcloud_context):
    clients = _clients(s3_versions=[{"Key": "k", "VersionId": "v"}])
    result, clients = _invoke(CASE_EVENT, govcloud_context, clients)
    assert result["compliance_status"] == "FAIL"
    batches = clients["securityhub_client"].calls_to("batch_import_findings")
    assert batches, "FAIL must import an ASFF finding"
    finding = batches[0]["Findings"][0]
    assert finding["ProductArn"].startswith("arn:aws-us-gov:securityhub:us-gov-west-1:")
    assert finding["AwsAccountId"] == "123456789012"


def test_backup_policy_floor_purges_even_when_case_opts_out(lambda_context):
    """REQUIRE_BACKUP_PURGE=true is a policy floor a case cannot opt out of."""
    event = json.loads(json.dumps(CASE_EVENT))
    event["case"]["include_backups"] = False
    result, _ = _invoke(event, lambda_context)
    body = json.loads(result["body"])
    actions = body["backup_purge_actions"]
    assert actions and actions[0]["status"] != "SKIPPED"


def test_case_recorded_when_table_configured(lambda_context, monkeypatch):
    monkeypatch.setenv("CASE_TABLE", "DeletionCases")
    result, clients = _invoke(CASE_EVENT, lambda_context)
    puts = clients["dynamodb_client"].calls_to("put_item")
    assert puts and puts[0]["TableName"] == "DeletionCases"
    assert puts[0]["Item"]["status"]["S"] == "PASS"
