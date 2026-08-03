"""Backup alignment & recovery testing (RTO/RPO).

FedRAMP CR26:
  KSI-RPL-RRO  define/review RTO and RPO
  KSI-RPL-ARP  align recovery plan to objectives
  KSI-RPL-ABO  align backups to objectives
  KSI-RPL-TRC  test recovery capability
  KSI-CNA-OFA  optimize for availability / rapid recovery

Lab evaluates:
  - Each critical asset has RTO/RPO
  - Backup frequency <= RPO
  - Vault encryption + vault lock
  - Restore drill completed and measured duration <= RTO

Event sources:
  * ``{"objectives": [...]}`` — the recovery-objective register, stamped
    ``data_source: "event"``. This is the primary and only real-data path:
    recovery *objectives* (RTO/RPO targets, drill outcomes, criticality) are
    declarations owned by the recovery plan — the AWS Backup API
    (list_backup_plans / list_recovery_points) reports what backups exist, not
    what was promised or drilled, so live discovery cannot honestly stand in
    for the register. An absent or empty register outside simulation is
    therefore CONFIG_ERROR ("no objectives supplied") — an empty
    backup-objective set is a configuration gap, never a PASS and never demo
    data.
  * ``{"mode": "simulation"}`` — fixed demo objectives, stamped as simulated.

Verdict semantics (fail closed):
  * ERROR — any objective row is malformed (missing/non-numeric fields,
    unparseable timestamps); the register could not be fully evaluated.
  * FAIL — any asset misses an objective, or the recovery plan is misaligned.
    ``last_restore_success`` goes through strict ``coerce_bool`` — the JSON
    string "false" is False, and an unreported/unknown value is treated as
    not-reported, which fails the drill objective for mission_critical assets.
  * PASS — every asset meets every objective and the plan is aligned.

Env contract: EVIDENCE_BUCKET, SNS_TOPIC_ARN, REQUIRE_VAULT_LOCK (default
true), REQUIRE_CMK (default true) — both read at handler time via strict
boolean parsing — and LOG_LEVEL.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from lab_common import (
    ConfigError,
    EvidenceWriter,
    RuntimeContext,
    Status,
    coerce_bool,
    get_bool_env,
    get_logger,
    new_run_id,
    parse_iso8601,
    publish_alert,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "12-backup-recovery-rto-rpo"
SCF_CONTROLS = ["BCD-01", "BCD-02", "BCD-11", "BCD-12", "CRY-05", "AST-02"]
FEDRAMP_KSI = ["KSI-RPL-RRO", "KSI-RPL-ARP", "KSI-RPL-ABO", "KSI-RPL-TRC", "KSI-CNA-OFA"]

logger = get_logger(LAB_ID)

# Mission-critical assets must run a restore drill at least quarterly.
MISSION_CRITICAL_RESTORE_TEST_MAX_AGE_DAYS = 90

_REQUIRED_FIELDS = ("asset_id", "asset_arn", "rto_minutes", "rpo_minutes", "backup_frequency_minutes")


@dataclass
class RecoveryObjective:
    asset_id: str
    asset_arn: str
    criticality: str  # mission_critical | high | medium
    rto_minutes: int
    rpo_minutes: int
    backup_frequency_minutes: int
    vault_name: str
    vault_locked: bool
    encrypted_with_cmk: bool
    last_restore_test_at: str | None
    last_restore_duration_minutes: float | None
    last_restore_success: bool | None


def _parse_objective(raw: dict[str, Any]) -> RecoveryObjective:
    """Validate and normalize one register row. Raises ValueError with a
    per-row detail on malformed input instead of leaking KeyError/ValueError
    out of the handler."""
    if not isinstance(raw, dict):
        raise ValueError("objective must be an object")
    missing = [f for f in _REQUIRED_FIELDS if f not in raw]
    if missing:
        raise ValueError(f"missing required field(s): {', '.join(missing)}")
    try:
        rto = int(raw["rto_minutes"])
        rpo = int(raw["rpo_minutes"])
        frequency = int(raw["backup_frequency_minutes"])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"rto/rpo/backup_frequency must be integer minutes: {exc}") from exc
    duration_raw = raw.get("last_restore_duration_minutes")
    try:
        duration = float(duration_raw) if duration_raw is not None else None
    except (TypeError, ValueError) as exc:
        raise ValueError(f"last_restore_duration_minutes must be numeric: {exc}") from exc
    last_test_raw = raw.get("last_restore_test_at")
    if last_test_raw is not None:
        if not isinstance(last_test_raw, str) or not last_test_raw.strip():
            raise ValueError("last_restore_test_at must be an ISO-8601 string or null")
        try:
            # parse_iso8601 treats naive timestamps as UTC — comparing them
            # against utc_now() raised TypeError in earlier lab code.
            last_test = parse_iso8601(last_test_raw).isoformat()
        except ValueError as exc:
            raise ValueError(f"unparseable last_restore_test_at {last_test_raw!r}: {exc}") from exc
    else:
        last_test = None
    return RecoveryObjective(
        asset_id=str(raw["asset_id"]),
        asset_arn=str(raw["asset_arn"]),
        criticality=str(raw.get("criticality", "medium")),
        rto_minutes=rto,
        rpo_minutes=rpo,
        backup_frequency_minutes=frequency,
        vault_name=str(raw.get("vault_name", "")),
        # Strict booleans throughout: the JSON string "false" is False, and
        # anything unrecognized counts as not-attested (fails closed).
        vault_locked=coerce_bool(raw.get("vault_locked")) is True,
        encrypted_with_cmk=coerce_bool(raw.get("encrypted_with_cmk")) is True,
        last_restore_test_at=last_test,
        last_restore_duration_minutes=duration,
        last_restore_success=coerce_bool(raw.get("last_restore_success")),
    )


def parse_objectives(
    raw_list: list[Any],
) -> tuple[list[RecoveryObjective], list[dict[str, Any]]]:
    """Parse the register, collecting per-row error details for malformed rows."""
    objectives: list[RecoveryObjective] = []
    errors: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_list):
        try:
            objectives.append(_parse_objective(raw))
        except ValueError as exc:
            asset_id = raw.get("asset_id", "unknown") if isinstance(raw, dict) else "unknown"
            errors.append({"index": index, "asset_id": asset_id, "error": str(exc)})
    return objectives, errors


def evaluate_asset(
    obj: RecoveryObjective, *, require_vault_lock: bool, require_cmk: bool
) -> dict[str, Any]:
    findings: list[str] = []
    if obj.backup_frequency_minutes > obj.rpo_minutes:
        findings.append(
            f"backup_frequency {obj.backup_frequency_minutes}m exceeds RPO {obj.rpo_minutes}m (KSI-RPL-ABO)"
        )
    if require_cmk and not obj.encrypted_with_cmk:
        findings.append("backup vault/recovery points not encrypted with CMK")
    if require_vault_lock and not obj.vault_locked:
        findings.append("backup vault lock not enabled (immutability)")
    if not obj.last_restore_test_at:
        findings.append("no restore test evidence (KSI-RPL-TRC)")
    else:
        if obj.last_restore_success is False:
            findings.append("last restore test failed (KSI-RPL-TRC)")
        elif obj.last_restore_success is None and obj.criticality == "mission_critical":
            findings.append(
                "restore test outcome not reported — mission_critical requires a "
                "recorded drill result (KSI-RPL-TRC)"
            )
        if (
            obj.last_restore_duration_minutes is not None
            and obj.last_restore_duration_minutes > obj.rto_minutes
        ):
            findings.append(
                f"restore took {obj.last_restore_duration_minutes}m > RTO {obj.rto_minutes}m (KSI-RPL-TRC/RRO)"
            )
        # Staleness: mission-critical must test at least quarterly (lab default 90d)
        if obj.criticality == "mission_critical":
            last = parse_iso8601(obj.last_restore_test_at)
            age_days = (utc_now() - last).total_seconds() / 86400.0
            if age_days > MISSION_CRITICAL_RESTORE_TEST_MAX_AGE_DAYS:
                findings.append(
                    f"restore test stale ({age_days:.0f}d > "
                    f"{MISSION_CRITICAL_RESTORE_TEST_MAX_AGE_DAYS}d) for mission_critical asset"
                )

    return {
        "asset_id": obj.asset_id,
        "asset_arn": obj.asset_arn,
        "criticality": obj.criticality,
        "rto_minutes": obj.rto_minutes,
        "rpo_minutes": obj.rpo_minutes,
        "status": "PASS" if not findings else "FAIL",
        "findings": findings,
        "objectives": asdict(obj),
    }


def build_recovery_plan_alignment(results: list[dict[str, Any]]) -> dict[str, Any]:
    """KSI-RPL-ARP: plan must cover every mission_critical/high asset with PASS path."""
    covered = [r for r in results if r["criticality"] in {"mission_critical", "high"}]
    failing = [r for r in covered if r["status"] == "FAIL"]
    return {
        "plan_name": "federal-cso-recovery-plan",
        "assets_in_plan": len(covered),
        "assets_failing_alignment": len(failing),
        "aligned": len(failing) == 0,
        "notes": (
            "Recovery plan steps must name vault, restore runbook, isolated account, "
            "and communications for each critical asset."
        ),
    }


def _simulation_objectives() -> list[dict[str, Any]]:
    return [
        {
            "asset_id": "federal-api-db",
            "asset_arn": "arn:aws-us-gov:rds:us-gov-west-1:123456789012:db:federal-api",
            "criticality": "mission_critical",
            "rto_minutes": 60,
            "rpo_minutes": 15,
            "backup_frequency_minutes": 15,
            "vault_name": "federal-vault",
            "vault_locked": True,
            "encrypted_with_cmk": True,
            "last_restore_test_at": utc_now().isoformat(),
            "last_restore_duration_minutes": 42,
            "last_restore_success": True,
        },
        {
            "asset_id": "legacy-file-bucket",
            "asset_arn": "arn:aws-us-gov:s3:::legacy-files-simulated",
            "criticality": "high",
            "rto_minutes": 240,
            "rpo_minutes": 60,
            "backup_frequency_minutes": 1440,  # daily — fails RPO
            "vault_name": "federal-vault",
            "vault_locked": False,
            "encrypted_with_cmk": True,
            "last_restore_test_at": None,
            "last_restore_duration_minutes": None,
            "last_restore_success": None,
        },
    ]


def handler(
    event: dict[str, Any],
    context: Any,
    s3_client: Any = None,
    sns_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        RuntimeContext.from_lambda(context)  # fail closed if we can't tell where we run
        require_vault_lock = get_bool_env("REQUIRE_VAULT_LOCK", default=True)
        require_cmk = get_bool_env("REQUIRE_CMK", default=True)

        raw = event.get("objectives") or []
        if simulation_requested(event):
            raw = raw or _simulation_objectives()
            data_source = "simulation"
        elif raw:
            data_source = "event"
        else:
            raise ConfigError(
                "no objectives supplied — an empty backup-objective register is a "
                "configuration gap, not a PASS; pass event.objectives"
            )

        objectives, errors = parse_objectives(raw)
        results = [
            evaluate_asset(o, require_vault_lock=require_vault_lock, require_cmk=require_cmk)
            for o in objectives
        ]
        plan = build_recovery_plan_alignment(results)
        failed = [r for r in results if r["status"] == "FAIL"]
        if errors:
            status = Status.ERROR
        elif failed or not plan["aligned"]:
            status = Status.FAIL
        else:
            status = Status.PASS

        evidence = {
            "lab_id": LAB_ID,
            "checked_at": utc_now().isoformat(),
            "status": status.value,
            "data_source": data_source,
            "asset_count": len(results),
            "failing_asset_count": len(failed),
            "malformed_count": len(errors),
            "failing_assets": failed,
            "results": results,
            "malformed_objectives": errors,
            "recovery_plan_alignment": plan,
            "policy": {
                "require_vault_lock": require_vault_lock,
                "require_cmk": require_cmk,
                "mission_critical_restore_test_max_age_days": (
                    MISSION_CRITICAL_RESTORE_TEST_MAX_AGE_DAYS
                ),
                "restore_environment": "isolated account / quarantined VPC",
            },
            "drill_procedure": [
                "1. Select recovery point <= RPO age",
                "2. Restore into isolated account",
                "3. Validate application health checks",
                "4. Measure elapsed time vs RTO",
                "5. Destroy restore artifacts; retain evidence",
            ],
            "scf_controls": SCF_CONTROLS,
            "fedramp_20x_ksi": FEDRAMP_KSI,
        }

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is not Status.PASS:
            publish_alert(
                LAB_ID,
                status,
                f"{len(failed)} of {len(results)} assets failing recovery objectives; "
                f"{len(errors)} malformed objective row(s)",
                sns_client=sns_client,
            )
        logger.info(
            "recovery objective evaluation complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "assets": len(results),
                "failing": len(failed),
                "malformed": len(errors),
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
