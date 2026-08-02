"""Non-human identity (NHI) credential inventory + rotation compliance.

Discovers IAM access keys older than MAX_KEY_AGE_DAYS and Secrets Manager
secrets lacking rotation — either rotation is disabled outright, or the last
rotation/change is older than the same threshold.

Event sources:
  * ``{"inventory": [...]}`` — a pre-collected credential inventory, e.g. from
    an external NHI platform (Okta/Descope M2M apps). Scored as supplied and
    stamped ``data_source: "event"``.
  * Scheduled sweep (missing or empty inventory) — live discovery via the IAM
    and Secrets Manager APIs, fully paginated, stamped ``data_source: "aws-api"``.
  * ``{"mode": "simulation"}`` — fixed demo rows, stamped as simulated. Demo
    data never enters any other path.

Inventory item schema: ``type``, ``principal``, ``credential_id``,
``created_at`` (ISO-8601; for secrets this is the last rotation/change time),
optional ``rotation_enabled``. ``rotation_enabled`` goes through strict
``coerce_bool``: False fails outright, None means the credential type has no
managed rotation (IAM access keys) and age alone is the control.

Verdict semantics (fail closed):
  * ERROR — any inventory item is malformed (missing/unparseable ``created_at``);
    the population could not be fully evaluated, so no PASS is possible.
  * FAIL — any credential exceeds the max age or has rotation disabled.
  * PASS — the whole population was checked and is clean.

Env contract: EVIDENCE_BUCKET, SNS_TOPIC_ARN, MAX_KEY_AGE_DAYS (default 90,
read at handler time — a malformed value is CONFIG_ERROR, never an INIT crash),
LOG_LEVEL.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from lab_common import (
    ConfigError,
    EvidenceWriter,
    RuntimeContext,
    Status,
    coerce_bool,
    get_int_env,
    get_logger,
    new_run_id,
    parse_iso8601,
    publish_alert,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "03-nhi-credential-rotation"
SCF_CONTROLS = ["IAC-15", "IAC-21", "CRY-01", "CFG-02"]
FEDRAMP_KSI = ["KSI-IAM-ELP", "KSI-IAM-JIT", "KSI-SVC-SEC"]

logger = get_logger(LAB_ID)


def _to_iso(value: Any) -> str:
    """boto3 returns datetime objects; event inventories carry ISO strings."""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value) if value else ""


def discover_iam_access_keys(iam_client: Any) -> list[dict[str, Any]]:
    """Inventory every access key of every IAM user.

    Fully paginated on both levels — a truncated pull would understate the
    credential population under audit.
    """
    items: list[dict[str, Any]] = []
    for user_page in iam_client.get_paginator("list_users").paginate():
        for user in user_page.get("Users", []):
            user_name = user.get("UserName", "")
            key_paginator = iam_client.get_paginator("list_access_keys")
            for key_page in key_paginator.paginate(UserName=user_name):
                for key in key_page.get("AccessKeyMetadata", []):
                    items.append({
                        "type": "iam_access_key",
                        "principal": user.get("Arn") or user_name or "unknown",
                        "credential_id": key.get("AccessKeyId", "unknown"),
                        "created_at": _to_iso(key.get("CreateDate")),
                        # IAM keys have no managed rotation; age is the control.
                        "rotation_enabled": None,
                        "key_status": key.get("Status"),
                    })
    return items


def discover_secrets(secretsmanager_client: Any) -> list[dict[str, Any]]:
    """Inventory Secrets Manager secrets with rotation state and last-rotation
    age (LastRotatedDate, falling back to LastChangedDate/CreatedDate)."""
    items: list[dict[str, Any]] = []
    for page in secretsmanager_client.get_paginator("list_secrets").paginate():
        for secret in page.get("SecretList", []):
            rotated = (
                secret.get("LastRotatedDate")
                or secret.get("LastChangedDate")
                or secret.get("CreatedDate")
            )
            items.append({
                "type": "secretsmanager",
                "principal": secret.get("ARN") or secret.get("Name") or "unknown",
                "credential_id": secret.get("Name", "unknown"),
                "created_at": _to_iso(rotated),
                "rotation_enabled": bool(secret.get("RotationEnabled", False)),
            })
    return items


def evaluate_item(
    item: dict[str, Any], max_key_age_days: int, now: datetime
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Score one inventory row. Returns ``(finding, None)`` for a well-formed
    row and ``(None, error_detail)`` for a malformed one — malformed rows must
    surface as ERROR, never crash the invocation or silently pass."""
    if not isinstance(item, dict):
        return None, {"item": repr(item), "error": "inventory item must be an object"}
    identity = {
        "type": item.get("type", "unknown"),
        "principal": item.get("principal", "unknown"),
        "credential_id": item.get("credential_id", "unknown"),
    }
    created_raw = item.get("created_at")
    if not isinstance(created_raw, str) or not created_raw.strip():
        return None, {**identity, "error": "missing created_at timestamp"}
    try:
        created = parse_iso8601(created_raw)
    except ValueError as exc:
        return None, {**identity, "error": f"unparseable created_at {created_raw!r}: {exc}"}

    age = (now - created).total_seconds() / 86400.0
    rotation_enabled = coerce_bool(item.get("rotation_enabled"))
    reasons: list[str] = []
    if age >= max_key_age_days:
        reasons.append(f"age {age:.1f}d exceeds max {max_key_age_days}d")
    if rotation_enabled is False:
        reasons.append("rotation not enabled")
    return {
        **identity,
        "created_at": created.isoformat(),
        "age_days": round(age, 1),
        "rotation_enabled": rotation_enabled,
        "stale": bool(reasons),
        "reasons": reasons,
    }, None


def build_evidence(
    findings: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    max_key_age_days: int,
    data_source: str,
) -> dict[str, Any]:
    stale = [f for f in findings if f["stale"]]
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
    if errors:
        status = Status.ERROR
    elif stale:
        status = Status.FAIL
    else:
        status = Status.PASS
    return {
        "lab_id": LAB_ID,
        "checked_at": utc_now().isoformat(),
        "status": status.value,
        "data_source": data_source,
        "policy_max_key_age_days": max_key_age_days,
        "inventory_count": len(findings) + len(errors),
        "evaluated_count": len(findings),
        "stale_count": len(stale),
        "malformed_count": len(errors),
        "inventory_by_type": by_type,
        # Complete lists — no silent truncation; the counts above are
        # authoritative and these arrays match them.
        "credential_findings": findings,
        "stale_credentials": stale,
        "malformed_items": errors,
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "actions_recommended": [
            "Rotate IAM access key via CreateAccessKey + retire old key",
            "Enable Secrets Manager rotation Lambda",
            "Shorten M2M token TTL in Okta/Descope",
        ],
    }


def _simulation_inventory() -> list[dict[str, Any]]:
    return [
        {
            "type": "iam_access_key",
            "principal": "arn:aws:iam::123456789012:user/ci-bot-simulated",
            "credential_id": "AKIASIMULATED0000001",
            "created_at": (utc_now() - timedelta(days=400)).isoformat(),
            "rotation_enabled": None,
        },
        {
            "type": "secretsmanager",
            "principal": "arn:aws:secretsmanager:us-east-1:123456789012:secret:app/db/credentials-simulated",
            "credential_id": "app/db/credentials-simulated",
            "created_at": utc_now().isoformat(),
            "rotation_enabled": True,
        },
    ]


def handler(
    event: dict[str, Any],
    context: Any,
    iam_client: Any = None,
    secretsmanager_client: Any = None,
    s3_client: Any = None,
    sns_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        RuntimeContext.from_lambda(context)  # fail closed if we can't tell where we run
        max_key_age_days = get_int_env("MAX_KEY_AGE_DAYS", default=90)

        inventory = event.get("inventory") or []
        if simulation_requested(event):
            inventory = inventory or _simulation_inventory()
            data_source = "simulation"
        elif inventory:
            data_source = "event"
        else:
            if iam_client is None:  # pragma: no cover - AWS only
                import boto3

                iam_client = boto3.client("iam")
            if secretsmanager_client is None:  # pragma: no cover - AWS only
                import boto3

                secretsmanager_client = boto3.client("secretsmanager")
            inventory = discover_iam_access_keys(iam_client) + discover_secrets(
                secretsmanager_client
            )
            data_source = "aws-api"

        now = utc_now()
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for item in inventory:
            finding, error = evaluate_item(item, max_key_age_days, now)
            if error is not None:
                errors.append(error)
            else:
                findings.append(finding)

        evidence = build_evidence(findings, errors, max_key_age_days, data_source)
        status = Status(evidence["status"])

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is not Status.PASS:
            publish_alert(
                LAB_ID,
                status,
                f"{evidence['stale_count']} stale credential(s) and "
                f"{evidence['malformed_count']} malformed item(s) across "
                f"{evidence['inventory_count']} inventoried",
                sns_client=sns_client,
            )
        logger.info(
            "nhi rotation sweep complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "inventory": evidence["inventory_count"],
                "stale": evidence["stale_count"],
                "malformed": evidence["malformed_count"],
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
