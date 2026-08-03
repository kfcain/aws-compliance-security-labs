"""KMS Encryption & Secrets Governance.

Validates the cryptographic governance floor:

  1. Every enabled, symmetric, customer-managed KMS key must have annual
     rotation enabled and a key policy with no unconditioned public
     (``Principal: "*"``) Allow statements.
  2. Every Secrets Manager secret must have rotation enabled and must have
     been rotated (or at least changed) within MAX_SECRET_AGE_DAYS
     (default 90).
  3. Zero CMKs AND zero secrets → NOT_APPLICABLE (nothing to govern).

Env contract: EVIDENCE_BUCKET, SNS_TOPIC_ARN, MAX_SECRET_AGE_DAYS, LOG_LEVEL.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from lab_common import (
    AsffEmitter,
    ConfigError,
    EvidenceWriter,
    RuntimeContext,
    Status,
    get_int_env,
    get_logger,
    new_run_id,
    parse_iso8601,
    publish_alert,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "06-kms-encryption-governance"
SCF_CONTROLS = ["CRY-01", "CRY-03", "CFG-02", "CLD-01"]
FEDRAMP_KSI = ["KSI-SVC-ENC", "KSI-SVC-SNT", "KSI-SVC-SEC"]

logger = get_logger(LAB_ID)


def _as_datetime(value: Any) -> datetime | None:
    """boto3 returns datetimes; event/simulated payloads may carry strings."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else parse_iso8601(value.isoformat())
    if isinstance(value, str):
        return parse_iso8601(value)
    return None


def list_customer_keys(kms_client: Any) -> list[dict[str, Any]]:
    """All enabled symmetric customer-managed keys (AWS-managed keys are
    rotated by AWS and out of governance scope)."""
    keys: list[dict[str, Any]] = []
    for page in kms_client.get_paginator("list_keys").paginate():
        for entry in page.get("Keys", []):
            metadata = kms_client.describe_key(KeyId=entry["KeyId"]).get("KeyMetadata", {})
            if metadata.get("KeyManager") != "CUSTOMER":
                continue
            if metadata.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                continue
            if not metadata.get("Enabled", False):
                continue
            keys.append(metadata)
    return keys


def _public_unconditioned_statements(policy_document: str) -> list[str]:
    """Statement Sids (or indexes) that allow Principal "*" without any
    Condition — a public key policy."""
    policy = json.loads(policy_document)
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    offenders: list[str] = []
    for index, statement in enumerate(statements):
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        is_public = principal == "*" or (
            isinstance(principal, dict) and principal.get("AWS") == "*"
        )
        if is_public and not statement.get("Condition"):
            offenders.append(str(statement.get("Sid", f"statement[{index}]")))
    return offenders


def evaluate_key(metadata: dict[str, Any], kms_client: Any) -> dict[str, Any]:
    key_id = metadata.get("KeyId", "unknown")
    violations: list[str] = []
    rotation = kms_client.get_key_rotation_status(KeyId=key_id)
    rotation_enabled = bool(rotation.get("KeyRotationEnabled"))
    if not rotation_enabled:
        violations.append(f"CMK {key_id}: annual key rotation is disabled")
    policy_document = kms_client.get_key_policy(
        KeyId=key_id, PolicyName="default"
    ).get("Policy", "{}")
    public_sids = _public_unconditioned_statements(policy_document)
    if public_sids:
        violations.append(
            f"CMK {key_id}: key policy allows Principal \"*\" without conditions "
            f"({', '.join(public_sids)})"
        )
    return {
        "key_id": key_id,
        "arn": metadata.get("Arn", ""),
        "rotation_enabled": rotation_enabled,
        "public_policy_statements": public_sids,
        "status": "FAIL" if violations else "PASS",
        "violations": violations,
    }


def list_secrets(secretsmanager_client: Any) -> list[dict[str, Any]]:
    secrets: list[dict[str, Any]] = []
    for page in secretsmanager_client.get_paginator("list_secrets").paginate():
        secrets.extend(page.get("SecretList", []))
    return secrets


def evaluate_secret(secret: dict[str, Any], max_age_days: int) -> dict[str, Any]:
    name = secret.get("Name", "unknown")
    violations: list[str] = []
    rotation_enabled = bool(secret.get("RotationEnabled"))
    if not rotation_enabled:
        violations.append(f"secret {name}: automatic rotation is disabled")
    last_rotated = _as_datetime(secret.get("LastRotatedDate")) or _as_datetime(
        secret.get("LastChangedDate")
    )
    age_days: float | None = None
    if last_rotated is None:
        violations.append(f"secret {name}: no rotation or change timestamp recorded")
    else:
        age_days = (utc_now() - last_rotated) / timedelta(days=1)
        if age_days > max_age_days:
            violations.append(
                f"secret {name}: last rotated/changed {age_days:.0f} days ago "
                f"(max {max_age_days})"
            )
    return {
        "name": name,
        "arn": secret.get("ARN", ""),
        "rotation_enabled": rotation_enabled,
        "age_days": round(age_days, 1) if age_days is not None else None,
        "status": "FAIL" if violations else "PASS",
        "violations": violations,
    }


def build_evidence(
    key_results: list[dict[str, Any]],
    secret_results: list[dict[str, Any]],
    *,
    max_secret_age_days: int,
    data_source: str,
) -> dict[str, Any]:
    violations = [v for r in key_results + secret_results for v in r["violations"]]
    if not key_results and not secret_results:
        status = Status.NOT_APPLICABLE
    elif violations:
        status = Status.FAIL
    else:
        status = Status.PASS
    return {
        "lab_id": LAB_ID,
        "checked_at": utc_now().isoformat(),
        "status": status.value,
        "data_source": data_source,
        "customer_managed_keys": {
            "count": len(key_results),
            "failing_count": sum(1 for r in key_results if r["status"] == "FAIL"),
            "results": key_results,
        },
        "secrets": {
            "count": len(secret_results),
            "failing_count": sum(1 for r in secret_results if r["status"] == "FAIL"),
            "results": secret_results,
        },
        "violations": violations,
        "violation_count": len(violations),
        "policy": {"max_secret_age_days": max_secret_age_days},
        "note": (
            "no customer-managed keys or secrets in this account/region — "
            "nothing to govern"
            if status is Status.NOT_APPLICABLE
            else None
        ),
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "methodology": {
            "keys": (
                "ListKeys/DescribeKey (customer-managed, symmetric, enabled) + "
                "GetKeyRotationStatus + GetKeyPolicy public-statement scan"
            ),
            "secrets": "ListSecrets — RotationEnabled + rotation/change age vs policy",
            "persistent_cadence": "daily EventBridge schedule",
        },
    }


def _simulation_dataset() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deterministic demo: one healthy CMK, one rotation-disabled CMK, one
    stale secret → FAIL."""
    keys = [
        {
            "key_id": "sim-key-healthy",
            "arn": "arn:aws:kms:us-east-1:123456789012:key/sim-key-healthy",
            "rotation_enabled": True,
            "public_policy_statements": [],
            "status": "PASS",
            "violations": [],
        },
        {
            "key_id": "sim-key-norotate",
            "arn": "arn:aws:kms:us-east-1:123456789012:key/sim-key-norotate",
            "rotation_enabled": False,
            "public_policy_statements": [],
            "status": "FAIL",
            "violations": ["CMK sim-key-norotate: annual key rotation is disabled"],
        },
    ]
    secrets = [
        {
            "name": "sim-stale-secret",
            "arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:sim-stale",
            "rotation_enabled": False,
            "age_days": 400.0,
            "status": "FAIL",
            "violations": ["secret sim-stale-secret: automatic rotation is disabled"],
        },
    ]
    return keys, secrets


def handler(
    event: dict[str, Any],
    context: Any,
    kms_client: Any = None,
    secretsmanager_client: Any = None,
    s3_client: Any = None,
    sns_client: Any = None,
    securityhub_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        runtime = RuntimeContext.from_lambda(context)
        max_secret_age_days = get_int_env("MAX_SECRET_AGE_DAYS", default=90)

        if simulation_requested(event):
            key_results, secret_results = _simulation_dataset()
            data_source = "simulation"
        else:
            if kms_client is None or secretsmanager_client is None:  # pragma: no cover
                import boto3

                kms_client = kms_client or boto3.client("kms")
                secretsmanager_client = secretsmanager_client or boto3.client("secretsmanager")
            key_results = [
                evaluate_key(metadata, kms_client)
                for metadata in list_customer_keys(kms_client)
            ]
            secret_results = [
                evaluate_secret(secret, max_secret_age_days)
                for secret in list_secrets(secretsmanager_client)
            ]
            data_source = "aws-api"

        evidence = build_evidence(
            key_results, secret_results,
            max_secret_age_days=max_secret_age_days,
            data_source=data_source,
        )
        status = Status(evidence["status"])

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is Status.FAIL:
            emitter = AsffEmitter(LAB_ID, runtime, client=securityhub_client)
            emitter.emit([emitter.build_finding(
                finding_id=f"crypto-governance/{run_id}",
                title="KMS / Secrets Manager governance violations",
                description=(
                    f"{evidence['customer_managed_keys']['failing_count']} CMK(s) and "
                    f"{evidence['secrets']['failing_count']} secret(s) violate the "
                    "rotation/key-policy floor."
                ),
                severity="HIGH",
                resource_type="AwsKmsKey",
                resource_id=f"account/{runtime.account_id}/crypto-governance",
                status=status,
            )])
        if status is Status.FAIL:
            publish_alert(
                LAB_ID,
                status,
                f"{evidence['violation_count']} cryptographic governance violation(s)",
                sns_client=sns_client,
            )
        logger.info(
            "crypto governance sweep complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "keys": evidence["customer_managed_keys"]["count"],
                "secrets": evidence["secrets"]["count"],
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
