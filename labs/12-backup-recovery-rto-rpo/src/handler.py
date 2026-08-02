"""
Backup alignment & recovery testing (RTO/RPO).

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
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


LAB_ID = "12-backup-recovery-rto-rpo"
SCF_CONTROLS = ["BCD-01", "BCD-02", "BCD-11", "BCD-12", "CRY-05", "AST-02"]
FEDRAMP_KSI = ["KSI-RPL-RRO", "KSI-RPL-ARP", "KSI-RPL-ABO", "KSI-RPL-TRC", "KSI-CNA-OFA"]

EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET", "")
REQUIRE_VAULT_LOCK = os.environ.get("REQUIRE_VAULT_LOCK", "true").lower() == "true"
REQUIRE_CMK = os.environ.get("REQUIRE_CMK", "true").lower() == "true"


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


def evaluate_asset(obj: RecoveryObjective) -> dict[str, Any]:
    findings: list[str] = []
    if obj.backup_frequency_minutes > obj.rpo_minutes:
        findings.append(
            f"backup_frequency {obj.backup_frequency_minutes}m exceeds RPO {obj.rpo_minutes}m (KSI-RPL-ABO)"
        )
    if REQUIRE_CMK and not obj.encrypted_with_cmk:
        findings.append("backup vault/recovery points not encrypted with CMK")
    if REQUIRE_VAULT_LOCK and not obj.vault_locked:
        findings.append("backup vault lock not enabled (immutability)")
    if not obj.last_restore_test_at:
        findings.append("no restore test evidence (KSI-RPL-TRC)")
    elif obj.last_restore_success is False:
        findings.append("last restore test failed")
    elif obj.last_restore_duration_minutes is not None and obj.last_restore_duration_minutes > obj.rto_minutes:
        findings.append(
            f"restore took {obj.last_restore_duration_minutes}m > RTO {obj.rto_minutes}m (KSI-RPL-TRC/RRO)"
        )

    # Staleness: mission-critical must test at least quarterly (lab default 90d)
    if obj.last_restore_test_at and obj.criticality == "mission_critical":
        last = datetime.fromisoformat(obj.last_restore_test_at.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - last).total_seconds() / 86400.0
        if age_days > 90:
            findings.append(f"restore test stale ({age_days:.0f}d > 90d) for mission_critical asset")

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


def demo_objectives() -> list[RecoveryObjective]:
    return [
        RecoveryObjective(
            asset_id="federal-api-db",
            asset_arn="arn:aws:rds:us-gov-west-1:123:db:federal-api",
            criticality="mission_critical",
            rto_minutes=60,
            rpo_minutes=15,
            backup_frequency_minutes=15,
            vault_name="federal-vault",
            vault_locked=True,
            encrypted_with_cmk=True,
            last_restore_test_at=datetime.now(timezone.utc).isoformat(),
            last_restore_duration_minutes=42,
            last_restore_success=True,
        ),
        RecoveryObjective(
            asset_id="legacy-file-bucket",
            asset_arn="arn:aws:s3:::legacy-files",
            criticality="high",
            rto_minutes=240,
            rpo_minutes=60,
            backup_frequency_minutes=1440,  # daily — fails RPO
            vault_name="federal-vault",
            vault_locked=False,
            encrypted_with_cmk=True,
            last_restore_test_at=None,
            last_restore_duration_minutes=None,
            last_restore_success=None,
        ),
    ]


def parse_objectives(raw_list: list[dict[str, Any]]) -> list[RecoveryObjective]:
    out: list[RecoveryObjective] = []
    for r in raw_list:
        out.append(
            RecoveryObjective(
                asset_id=r["asset_id"],
                asset_arn=r["asset_arn"],
                criticality=r.get("criticality", "medium"),
                rto_minutes=int(r["rto_minutes"]),
                rpo_minutes=int(r["rpo_minutes"]),
                backup_frequency_minutes=int(r["backup_frequency_minutes"]),
                vault_name=r.get("vault_name", ""),
                vault_locked=bool(r.get("vault_locked", False)),
                encrypted_with_cmk=bool(r.get("encrypted_with_cmk", False)),
                last_restore_test_at=r.get("last_restore_test_at"),
                last_restore_duration_minutes=(
                    float(r["last_restore_duration_minutes"])
                    if r.get("last_restore_duration_minutes") is not None
                    else None
                ),
                last_restore_success=r.get("last_restore_success"),
            )
        )
    return out


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


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    raw = event.get("objectives")
    objectives = parse_objectives(raw) if raw else demo_objectives()
    results = [evaluate_asset(o) for o in objectives]
    plan = build_recovery_plan_alignment(results)
    failed = [r for r in results if r["status"] == "FAIL"]
    evidence = {
        "lab_id": LAB_ID,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if not failed and plan["aligned"] else "FAIL",
        "asset_count": len(results),
        "failing_assets": failed,
        "results": results,
        "recovery_plan_alignment": plan,
        "policy": {
            "require_vault_lock": REQUIRE_VAULT_LOCK,
            "require_cmk": REQUIRE_CMK,
            "mission_critical_restore_test_max_age_days": 90,
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
    print(json.dumps({"status": evidence["status"], "failing": len(failed)}))
    return {"statusCode": 200, "body": json.dumps(evidence)}
