"""Immutable Audit Evidence Pipeline.

Validates that the audit trail exists and that its evidence path is
tamper-resistant:

  1. CloudTrail: at least one trail (none → FAIL — the account has no audit
     pipeline), each trail IsLogging with LogFileValidationEnabled, at least
     one multi-region trail, KMS encryption recorded (unencrypted → violation).
  2. Bucket immutability posture for each trail's S3 bucket AND the lab's own
     EVIDENCE_BUCKET: full PublicAccessBlock, default encryption, versioning
     Enabled, and (for trail buckets) S3 Object Lock — a trail bucket without
     Object Lock is not immutable evidence.

Env contract: EVIDENCE_BUCKET, SNS_TOPIC_ARN, LOG_LEVEL.
"""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from lab_common import (
    AsffEmitter,
    ConfigError,
    EvidenceWriter,
    RuntimeContext,
    Status,
    get_logger,
    new_run_id,
    publish_alert,
    require_env,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "07-cloudtrail-evidence-pipeline"
SCF_CONTROLS = ["MON-01", "MON-02", "CPL-02", "CHG-01"]
FEDRAMP_KSI = ["KSI-MLA-OSM", "KSI-AFR-PVL", "KSI-CMT-CHG"]

logger = get_logger(LAB_ID)

_MISSING_CODES = {
    "ObjectLockConfigurationNotFoundError",
    "ServerSideEncryptionConfigurationNotFoundError",
    "NoSuchPublicAccessBlockConfiguration",
}


def evaluate_trails(cloudtrail_client: Any) -> tuple[list[dict[str, Any]], list[str]]:
    trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    violations: list[str] = []
    results: list[dict[str, Any]] = []
    if not trails:
        violations.append(
            "no CloudTrail trail in this account/region — there is no audit pipeline"
        )
    for trail in trails:
        name = trail.get("Name", "unknown")
        trail_violations: list[str] = []
        status = cloudtrail_client.get_trail_status(Name=trail.get("TrailARN") or name)
        if not status.get("IsLogging"):
            trail_violations.append(f"trail {name}: logging is STOPPED")
        if not trail.get("LogFileValidationEnabled"):
            trail_violations.append(f"trail {name}: log file validation is disabled")
        if not trail.get("KmsKeyId"):
            trail_violations.append(f"trail {name}: log files are not KMS-encrypted")
        results.append({
            "name": name,
            "trail_arn": trail.get("TrailARN", ""),
            "s3_bucket": trail.get("S3BucketName", ""),
            "is_logging": bool(status.get("IsLogging")),
            "log_file_validation": bool(trail.get("LogFileValidationEnabled")),
            "multi_region": bool(trail.get("IsMultiRegionTrail")),
            "kms_encrypted": bool(trail.get("KmsKeyId")),
            "violations": trail_violations,
        })
        violations.extend(trail_violations)
    if trails and not any(t["multi_region"] for t in results):
        violations.append("no multi-region trail — events outside this region are unaudited")
    return results, violations


def _get_or_none(s3_client: Any, method: str, bucket: str) -> Any:
    """Bucket sub-resource read where 'not configured' is data, not an error."""
    try:
        return getattr(s3_client, method)(Bucket=bucket)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in _MISSING_CODES:
            return None
        raise


def bucket_immutability_posture(
    bucket: str, s3_client: Any, *, require_object_lock: bool
) -> dict[str, Any]:
    violations: list[str] = []

    pab_response = _get_or_none(s3_client, "get_public_access_block", bucket)
    pab = (pab_response or {}).get("PublicAccessBlockConfiguration", {})
    pab_ok = all(
        pab.get(flag)
        for flag in (
            "BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets",
        )
    )
    if not pab_ok:
        violations.append(f"bucket {bucket}: public access block is not fully enabled")

    encryption = _get_or_none(s3_client, "get_bucket_encryption", bucket)
    encrypted = bool(
        (encryption or {})
        .get("ServerSideEncryptionConfiguration", {})
        .get("Rules")
    )
    if not encrypted:
        violations.append(f"bucket {bucket}: no default encryption configuration")

    versioning = s3_client.get_bucket_versioning(Bucket=bucket)
    versioning_enabled = versioning.get("Status") == "Enabled"
    if not versioning_enabled:
        violations.append(f"bucket {bucket}: versioning is not Enabled")

    lock = _get_or_none(s3_client, "get_object_lock_configuration", bucket)
    object_lock = (
        (lock or {}).get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled"
    )
    if require_object_lock and not object_lock:
        violations.append(
            f"bucket {bucket}: S3 Object Lock is not enabled — trail evidence is not "
            "WORM-immutable"
        )

    return {
        "bucket": bucket,
        "public_access_block": pab_ok,
        "encrypted": encrypted,
        "versioning_enabled": versioning_enabled,
        "object_lock_enabled": object_lock,
        "object_lock_required": require_object_lock,
        "violations": violations,
    }


def build_evidence(
    trail_results: list[dict[str, Any]],
    trail_violations: list[str],
    bucket_results: list[dict[str, Any]],
    data_source: str,
) -> dict[str, Any]:
    bucket_violations = [v for r in bucket_results for v in r["violations"]]
    violations = trail_violations + bucket_violations
    status = Status.FAIL if violations else Status.PASS
    return {
        "lab_id": LAB_ID,
        "checked_at": utc_now().isoformat(),
        "status": status.value,
        "data_source": data_source,
        "trails": trail_results,
        "trail_count": len(trail_results),
        "buckets": bucket_results,
        "violations": violations,
        "violation_count": len(violations),
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "methodology": {
            "trails": (
                "DescribeTrails (no shadow trails) + GetTrailStatus — IsLogging, "
                "log file validation, KMS, multi-region coverage"
            ),
            "immutability": (
                "Per-bucket PublicAccessBlock + default encryption + versioning; "
                "Object Lock required on trail buckets"
            ),
            "persistent_cadence": "daily EventBridge schedule",
        },
    }


def _simulation_dataset() -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    """Deterministic demo: one healthy multi-region trail with a locked bucket."""
    trail_results = [{
        "name": "sim-org-trail",
        "trail_arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/sim-org-trail",
        "s3_bucket": "sim-trail-evidence",
        "is_logging": True,
        "log_file_validation": True,
        "multi_region": True,
        "kms_encrypted": True,
        "violations": [],
    }]
    bucket_results = [{
        "bucket": "sim-trail-evidence",
        "public_access_block": True,
        "encrypted": True,
        "versioning_enabled": True,
        "object_lock_enabled": True,
        "object_lock_required": True,
        "violations": [],
    }]
    return trail_results, [], bucket_results


def handler(
    event: dict[str, Any],
    context: Any,
    cloudtrail_client: Any = None,
    s3_client: Any = None,
    sns_client: Any = None,
    securityhub_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        runtime = RuntimeContext.from_lambda(context)

        if simulation_requested(event):
            trail_results, trail_violations, bucket_results = _simulation_dataset()
            data_source = "simulation"
        else:
            evidence_bucket = require_env("EVIDENCE_BUCKET")
            if cloudtrail_client is None or s3_client is None:  # pragma: no cover
                import boto3

                cloudtrail_client = cloudtrail_client or boto3.client("cloudtrail")
                s3_client = s3_client or boto3.client("s3")
            trail_results, trail_violations = evaluate_trails(cloudtrail_client)
            buckets_to_check: list[tuple[str, bool]] = []
            seen: set[str] = set()
            for trail in trail_results:
                bucket = trail["s3_bucket"]
                if bucket and bucket not in seen:
                    seen.add(bucket)
                    buckets_to_check.append((bucket, True))  # trail evidence must be WORM
            if evidence_bucket not in seen:
                # The lab's own evidence bucket: Object Lock recommended but
                # parameterized in IaC, so posture is recorded, not enforced.
                buckets_to_check.append((evidence_bucket, False))
            bucket_results = [
                bucket_immutability_posture(bucket, s3_client, require_object_lock=required)
                for bucket, required in buckets_to_check
            ]
            data_source = "aws-api"

        evidence = build_evidence(trail_results, trail_violations, bucket_results, data_source)
        status = Status(evidence["status"])

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is Status.FAIL:
            emitter = AsffEmitter(LAB_ID, runtime, client=securityhub_client)
            emitter.emit([emitter.build_finding(
                finding_id=f"evidence-pipeline/{run_id}",
                title="Audit evidence pipeline is not immutable or not logging",
                description=(
                    f"{evidence['violation_count']} violation(s) across "
                    f"{evidence['trail_count']} trail(s) and "
                    f"{len(evidence['buckets'])} evidence bucket(s)."
                ),
                severity="HIGH",
                resource_type="AwsCloudTrailTrail",
                resource_id=f"account/{runtime.account_id}/audit-pipeline",
                status=status,
            )])
            publish_alert(
                LAB_ID,
                status,
                f"{evidence['violation_count']} audit-pipeline violation(s)",
                sns_client=sns_client,
            )
        logger.info(
            "evidence pipeline check complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "trails": evidence["trail_count"],
                "violations": evidence["violation_count"],
            }},
        )
        return respond(status, evidence)
    except ConfigError as exc:
        logger.error(
            "configuration error",
            extra={"extra_fields": {"run_id": run_id, "error": str(exc)}},
        )
        return respond(Status.CONFIG_ERROR, {"lab_id": LAB_ID, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001 - fail closed, never crash the invocation
        logger.exception("unhandled error")
        return respond(Status.ERROR, {"lab_id": LAB_ID, "error": str(exc), "run_id": run_id})
