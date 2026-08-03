"""Behavior tests for lab 17 (Terraform DR readiness & state-backend resilience)."""
from __future__ import annotations

import io
import json

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("17-terraform-dr-readiness")

RESILIENT_BACKEND = {
    "backend_type": "s3", "bucket": "tf-state", "region": "us-east-1",
    "versioning": True, "kms_encrypted": True, "cross_region_replication": True,
    "locking": True, "lock_mechanism": "dynamodb",
}
DURABLE_STORE = {
    "address": "aws_dynamodb_table.sessions", "store_type": "aws_dynamodb_table",
    "critical": True, "cross_region_replication": True,
}


def _descriptor(**overrides):
    d = {
        "backend": dict(RESILIENT_BACKEND),
        "primary_region": "us-east-1",
        "recovery_region": "us-west-2",
        "data_stores": [dict(DURABLE_STORE)],
        "failover_routing": True,
        "declared_rto_minutes": 30,
        "declared_rpo_minutes": 15,
    }
    d.update(overrides)
    return d


def _invoke(event, lambda_context, s3=None):
    s3, sns = s3 or FakeClient(), FakeClient()
    hub = FakeClient(responses={"batch_import_findings": {"SuccessCount": 1}})
    result = handler_mod.handler(
        event, lambda_context, s3_client=s3, sns_client=sns, securityhub_client=hub,
    )
    return result, s3, sns, hub


def _codes(body):
    return {f["code"] for f in body["findings"]}


def test_fully_ready_passes(lambda_context):
    result, *_ = _invoke({"descriptor": _descriptor()}, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "PASS"
    assert body["finding_count"] == 0


def test_local_backend_is_critical(lambda_context):
    d = _descriptor(backend={"backend_type": "local"})
    result, _, sns, hub = _invoke({"descriptor": d}, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert "state-backend-local" in _codes(body)
    assert body["findings_by_severity"].get("critical") == 1
    assert hub.calls_to("batch_import_findings") and sns.calls_to("publish")


def test_backend_without_replication_and_lock_fails(lambda_context):
    backend = dict(RESILIENT_BACKEND, cross_region_replication=False, locking=False)
    result, *_ = _invoke({"descriptor": _descriptor(backend=backend)}, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert {"state-backend-no-replication", "state-backend-no-lock"} <= _codes(body)


def test_critical_store_without_durability_is_critical(lambda_context):
    store = {"address": "aws_s3_bucket.cui", "store_type": "aws_s3_bucket", "critical": True}
    result, *_ = _invoke({"descriptor": _descriptor(data_stores=[store])}, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert "store-not-cross-region-durable" in _codes(body)


def test_pitr_plus_cross_region_backup_is_durable(lambda_context):
    store = {"address": "aws_s3_bucket.cui", "store_type": "aws_s3_bucket", "critical": True,
             "point_in_time_recovery": True, "cross_region_backup": True}
    result, *_ = _invoke({"descriptor": _descriptor(data_stores=[store])}, lambda_context)
    body = json.loads(result["body"])
    assert "store-not-cross-region-durable" not in _codes(body)
    assert result["compliance_status"] == "PASS"


def test_recovery_region_equals_primary_fails(lambda_context):
    result, *_ = _invoke({"descriptor": _descriptor(recovery_region="us-east-1")}, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert "recovery-region-equals-primary" in _codes(body)


def test_missing_failover_routing_severity_scales_with_rto(lambda_context):
    tight = _descriptor(failover_routing=False, declared_rto_minutes=30)
    result, *_ = _invoke({"descriptor": tight}, lambda_context)
    body = json.loads(result["body"])
    nf = next(f for f in body["findings"] if f["code"] == "no-failover-routing")
    assert nf["severity"] == "high"  # tight RTO -> high
    assert result["compliance_status"] == "FAIL"


def test_rpo_target_unmet_fails(lambda_context, monkeypatch):
    monkeypatch.setenv("RPO_TARGET_MINUTES", "5")
    result, *_ = _invoke({"descriptor": _descriptor(declared_rpo_minutes=60)}, lambda_context)
    body = json.loads(result["body"])
    assert "rpo-target-unmet" in _codes(body)
    assert result["compliance_status"] == "FAIL"


def test_descriptor_from_s3(lambda_context, monkeypatch):
    monkeypatch.setenv("DESCRIPTOR_BUCKET", "dr")
    monkeypatch.setenv("DESCRIPTOR_KEY", "prod/dr.json")
    d = _descriptor(backend={"backend_type": "local"})
    s3 = FakeClient(responses={"get_object": {"Body": io.BytesIO(json.dumps(d).encode())}})
    result, s3, *_ = _invoke({}, lambda_context, s3=s3)
    body = json.loads(result["body"])
    assert body["data_source"] == "s3"
    assert s3.calls_to("get_object")[0]["Key"] == "prod/dr.json"
    assert result["compliance_status"] == "FAIL"


def test_no_descriptor_is_config_error(lambda_context):
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_missing_primary_region_is_error(lambda_context):
    result, *_ = _invoke({"descriptor": {"backend": RESILIENT_BACKEND}}, lambda_context)
    assert result["compliance_status"] == "ERROR"


def test_bad_fail_severity_is_config_error(lambda_context, monkeypatch):
    monkeypatch.setenv("FAIL_SEVERITY", "apocalyptic")
    result, *_ = _invoke({"descriptor": _descriptor()}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_provenance_and_manifest(lambda_context, monkeypatch):
    monkeypatch.setenv("TERRAFORM_COMMIT", "cafe1234")
    result, *_ = _invoke({"descriptor": _descriptor()}, lambda_context)
    body = json.loads(result["body"])
    prov = body["provenance"]
    assert prov["terraform_commit"] == "cafe1234"
    assert len(prov["evidence_manifest_sha256"]) == 64
    assert handler_mod.evidence_manifest_sha256(body) == prov["evidence_manifest_sha256"]


def test_assurance_case_maps_cp_objectives_and_status(lambda_context):
    # a backend-only failure should mark CFG-01 other-than-satisfied but leave
    # the BCD controls satisfied when the architecture is sound
    d = _descriptor(backend=dict(RESILIENT_BACKEND, versioning=False))
    result, *_ = _invoke({"descriptor": d}, lambda_context)
    case = {c["scf_control"]: c for c in json.loads(result["body"])["assurance_case"]}
    assert "CP-09" in case["BCD-11"]["nist_800_53_r5_objectives"]
    assert case["CFG-01"]["status"] == "OTHER-THAN-SATISFIED"
    assert case["BCD-11"]["status"] == "SATISFIED"


def test_simulation_is_stamped_and_fails(lambda_context):
    result, *_ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    # sim has a non-durable critical S3 store -> critical finding
    assert result["compliance_status"] == "FAIL"
    assert "store-not-cross-region-durable" in _codes(body)


def test_evidence_written(lambda_context):
    result, s3, *_ = _invoke({"mode": "simulation"}, lambda_context)
    assert s3.calls_to("put_object")
    assert json.loads(result["body"])["evidence_uri"].startswith("s3://test-evidence-bucket/")
