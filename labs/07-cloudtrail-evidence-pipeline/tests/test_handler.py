"""Behavior tests for lab 07 (immutable audit evidence pipeline)."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("07-cloudtrail-evidence-pipeline")

HEALTHY_TRAIL = {
    "Name": "org-trail",
    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail",
    "S3BucketName": "trail-bucket",
    "LogFileValidationEnabled": True,
    "IsMultiRegionTrail": True,
    "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/k",
}


def _not_found(code):
    return ClientError({"Error": {"Code": code}}, "GetBucketThing")


def _s3(*, pab=True, encrypted=True, versioned=True, locked=True):
    responses = {
        "get_public_access_block": (
            {"PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "BlockPublicPolicy": True,
                "IgnorePublicAcls": True, "RestrictPublicBuckets": True,
            }} if pab else _not_found("NoSuchPublicAccessBlockConfiguration")
        ),
        "get_bucket_encryption": (
            {"ServerSideEncryptionConfiguration": {"Rules": [{}]}}
            if encrypted else _not_found("ServerSideEncryptionConfigurationNotFoundError")
        ),
        "get_bucket_versioning": {"Status": "Enabled" if versioned else "Suspended"},
        "get_object_lock_configuration": (
            {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}
            if locked else _not_found("ObjectLockConfigurationNotFoundError")
        ),
        "put_object": {},
    }
    return FakeClient(responses=responses)


def _cloudtrail(trails=None, is_logging=True):
    return FakeClient(responses={
        "describe_trails": {"trailList": trails if trails is not None else [HEALTHY_TRAIL]},
        "get_trail_status": {"IsLogging": is_logging},
    })


def _invoke(event, lambda_context, ct=None, s3=None):
    ct = ct or _cloudtrail()
    s3 = s3 or _s3()
    sns = FakeClient()
    hub = FakeClient(responses={"batch_import_findings": {"SuccessCount": 1}})
    result = handler_mod.handler(
        event, lambda_context,
        cloudtrail_client=ct, s3_client=s3, sns_client=sns, securityhub_client=hub,
    )
    return result, s3, sns, hub


def test_healthy_pipeline_passes(lambda_context):
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "PASS"


def test_no_trail_fails(lambda_context):
    result, _, sns, hub = _invoke({}, lambda_context, ct=_cloudtrail(trails=[]))
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert "no CloudTrail trail" in body["violations"][0]
    assert hub.calls_to("batch_import_findings") and sns.calls_to("publish")


def test_logging_stopped_fails(lambda_context):
    result, *_ = _invoke({}, lambda_context, ct=_cloudtrail(is_logging=False))
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert any("STOPPED" in v for v in body["violations"])


def test_log_file_validation_off_fails(lambda_context):
    trail = dict(HEALTHY_TRAIL, LogFileValidationEnabled=False)
    result, *_ = _invoke({}, lambda_context, ct=_cloudtrail(trails=[trail]))
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert any("log file validation" in v for v in body["violations"])


def test_unencrypted_trail_fails(lambda_context):
    trail = dict(HEALTHY_TRAIL)
    del trail["KmsKeyId"]
    result, *_ = _invoke({}, lambda_context, ct=_cloudtrail(trails=[trail]))
    assert result["compliance_status"] == "FAIL"


def test_no_multi_region_trail_fails(lambda_context):
    trail = dict(HEALTHY_TRAIL, IsMultiRegionTrail=False)
    result, *_ = _invoke({}, lambda_context, ct=_cloudtrail(trails=[trail]))
    body = json.loads(result["body"])
    assert any("multi-region" in v for v in body["violations"])


def test_missing_object_lock_on_trail_bucket_fails(lambda_context):
    result, *_ = _invoke({}, lambda_context, s3=_s3(locked=False))
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert any("Object Lock" in v for v in body["violations"])


def test_lab_evidence_bucket_checked_but_lock_optional(lambda_context):
    """The lab's own EVIDENCE_BUCKET is posture-checked; Object Lock is
    recorded, required only for trail buckets."""
    result, s3, *_ = _invoke({}, lambda_context)
    body = json.loads(result["body"])
    checked = {b["bucket"] for b in body["buckets"]}
    assert checked == {"trail-bucket", "test-evidence-bucket"}
    lab_bucket = next(b for b in body["buckets"] if b["bucket"] == "test-evidence-bucket")
    assert lab_bucket["object_lock_required"] is False


def test_missing_pab_or_versioning_fails(lambda_context):
    result, *_ = _invoke({}, lambda_context, s3=_s3(pab=False, versioned=False))
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert any("public access block" in v for v in body["violations"])
    assert any("versioning" in v for v in body["violations"])


def test_simulation_is_stamped(lambda_context):
    result, *_ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    assert result["compliance_status"] == "PASS"


def test_sdk_error_is_error_status(lambda_context):
    ct = FakeClient(responses={"describe_trails": RuntimeError("boom")})
    result, *_ = _invoke({}, lambda_context, ct=ct)
    assert result["compliance_status"] == "ERROR"
