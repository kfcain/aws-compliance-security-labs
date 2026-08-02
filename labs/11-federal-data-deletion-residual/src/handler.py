"""
Federal customer data deletion & residual-data proof.

FedRAMP CR26 Class C:
  - KSI-SVC-RUD: remove unwanted federal customer data promptly (incl. backups when appropriate)
  - KSI-SVC-PRR: after changes, review/remove residual elements that harm federal data CIA

Flow:
  1. Ingest deletion case (tenant_id / agency_id / data classes)
  2. Resolve catalog of live stores + backup selections tagged to that tenant
  3. Purge live objects (S3, DynamoDB, logical RDS rows)
  4. Expire / delete backup recovery points in scope
  5. Residual scan (Athena / ListObjects / Query) until zero hits or FAIL
  6. Emit evidence JSON + Security Hub ASFF
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

LAB_ID = "11-federal-data-deletion-residual"
SCF_CONTROLS = ["DCH-01", "DCH-09", "DCH-06", "BCD-11", "CRY-05", "CLD-01"]
FEDRAMP_KSI = ["KSI-SVC-RUD", "KSI-SVC-PRR", "KSI-SVC-SIN", "KSI-AFR-PVL"]

EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET", "")
AWS_ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", "000000000000")
REQUIRE_BACKUP_PURGE = os.environ.get("REQUIRE_BACKUP_PURGE", "true").lower() == "true"
TENANT_TAG_KEY = os.environ.get("TENANT_TAG_KEY", "federal_tenant_id")


@dataclass
class DataStoreRef:
    service: str  # s3 | dynamodb | rds | opensearch | backup
    arn_or_name: str
    tenant_id: str
    contains_federal_data: bool = True
    backup_vault: str | None = None


@dataclass
class DeletionCase:
    case_id: str
    agency_id: str
    tenant_id: str
    reason: str  # offboarding | spill | customer_request
    requested_at: str
    include_backups: bool = True
    data_classes: list[str] = field(default_factory=lambda: ["CUI", "federal_customer"])


@dataclass
class PurgeAction:
    store: str
    action: str
    status: str
    detail: str


@dataclass
class ResidualHit:
    store: str
    locator: str
    confidence: str


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def validate_case(raw: dict[str, Any]) -> DeletionCase:
    tenant = str(raw.get("tenant_id") or "").strip()
    if not tenant or not re.match(r"^[A-Za-z0-9_.:-]{3,128}$", tenant):
        raise ValueError("tenant_id is required and must be a safe identifier")
    reason = str(raw.get("reason") or "customer_request")
    if reason not in {"offboarding", "spill", "customer_request"}:
        raise ValueError("reason must be offboarding|spill|customer_request")
    return DeletionCase(
        case_id=str(raw.get("case_id") or f"case-{tenant}-{int(datetime.now(UTC).timestamp())}"),
        agency_id=str(raw.get("agency_id") or "unknown-agency"),
        tenant_id=tenant,
        reason=reason,
        requested_at=str(raw.get("requested_at") or now_iso()),
        include_backups=bool(raw.get("include_backups", True)),
        data_classes=list(raw.get("data_classes") or ["CUI", "federal_customer"]),
    )


def resolve_catalog(tenant_id: str, event_catalog: list[dict[str, Any]] | None) -> list[DataStoreRef]:
    """Resolve tagged stores. Production: Config/Athena inventory. Lab: event catalog or demo."""
    if event_catalog:
        return [
            DataStoreRef(
                service=i["service"],
                arn_or_name=i["arn_or_name"],
                tenant_id=tenant_id,
                contains_federal_data=bool(i.get("contains_federal_data", True)),
                backup_vault=i.get("backup_vault"),
            )
            for i in event_catalog
            if i.get("tenant_id", tenant_id) == tenant_id
        ]
    # Demo federal tenant footprint
    return [
        DataStoreRef("s3", f"s3://federal-app-data/{tenant_id}/", tenant_id, True, "federal-vault"),
        DataStoreRef("dynamodb", f"arn:aws:dynamodb:us-gov-west-1:{AWS_ACCOUNT_ID}:table/TenantData", tenant_id, True, "federal-vault"),
        DataStoreRef("rds", f"arn:aws:rds:us-gov-west-1:{AWS_ACCOUNT_ID}:db:app-db", tenant_id, True, "federal-vault"),
        DataStoreRef("backup", "federal-vault", tenant_id, True, "federal-vault"),
    ]


def purge_live_store(store: DataStoreRef) -> PurgeAction:
    """
    Idempotent purge stub. Wire boto3:
      s3: list+delete by prefix
      dynamodb: Query tenant partition + BatchWriteItem delete
      rds: SQL delete by tenant with transaction + row count evidence
    """
    if not store.contains_federal_data:
        return PurgeAction(store.arn_or_name, "skip", "SKIPPED", "not marked federal")
    return PurgeAction(
        store=store.arn_or_name,
        action=f"purge_{store.service}",
        status="PURGED_PLACEHOLDER",
        detail=f"Would purge objects/rows for {TENANT_TAG_KEY}={store.tenant_id}",
    )


def purge_backups(case: DeletionCase, stores: list[DataStoreRef]) -> list[PurgeAction]:
    if not case.include_backups and not REQUIRE_BACKUP_PURGE:
        return [PurgeAction("backup", "skip", "SKIPPED", "include_backups=false")]
    vaults = sorted({s.backup_vault for s in stores if s.backup_vault})
    actions = []
    for vault in vaults:
        actions.append(
            PurgeAction(
                store=vault or "unknown-vault",
                action="expire_recovery_points",
                status="PURGED_PLACEHOLDER",
                detail=(
                    f"Would delete/expire AWS Backup recovery points tagged "
                    f"{TENANT_TAG_KEY}={case.tenant_id} (spill/offboarding)"
                ),
            )
        )
    if not actions:
        actions.append(
            PurgeAction("backup", "verify", "WARN", "No backup vault mapped — FAIL closed in production")
        )
    return actions


def residual_scan(tenant_id: str, stores: list[DataStoreRef], simulate_hits: list[dict[str, Any]] | None) -> list[ResidualHit]:
    """
    Production checks:
      - S3 inventory / Athena: keys still under tenant prefix
      - DynamoDB: Query still returns items
      - Backup: ListRecoveryPointsByResource still lists tenant-tagged points
    """
    if simulate_hits is not None:
        return [ResidualHit(**h) for h in simulate_hits]
    # Clean demo path
    _ = stores
    _ = tenant_id
    return []


def build_evidence(
    case: DeletionCase,
    stores: list[DataStoreRef],
    live_actions: list[PurgeAction],
    backup_actions: list[PurgeAction],
    residuals: list[ResidualHit],
) -> dict[str, Any]:
    backup_ok = all(a.status in {"PURGED_PLACEHOLDER", "SKIPPED", "OK"} for a in backup_actions)
    if REQUIRE_BACKUP_PURGE and case.include_backups:
        backup_ok = all(a.status in {"PURGED_PLACEHOLDER", "OK"} for a in backup_actions) and not any(
            a.status == "WARN" for a in backup_actions
        )
    status = "PASS" if not residuals and backup_ok else "FAIL"
    return {
        "lab_id": LAB_ID,
        "checked_at": now_iso(),
        "status": status,
        "case": asdict(case),
        "catalog_count": len(stores),
        "catalog": [asdict(s) for s in stores],
        "live_purge_actions": [asdict(a) for a in live_actions],
        "backup_purge_actions": [asdict(a) for a in backup_actions],
        "residual_hits": [asdict(h) for h in residuals],
        "residual_hit_count": len(residuals),
        "policy": {
            "require_backup_purge": REQUIRE_BACKUP_PURGE,
            "tenant_tag_key": TENANT_TAG_KEY,
            "class_c_ksis": ["KSI-SVC-RUD", "KSI-SVC-PRR"],
            "federal_data_rule": (
                "Unwanted federal customer data must be removed promptly from live "
                "systems and backups when appropriate; prove zero residual hits."
            ),
        },
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "acceptance": {
            "zero_residual_hits": len(residuals) == 0,
            "backup_path_executed": backup_ok,
            "evidence_retained_days_min": 365,
        },
    }


def to_asff(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    if evidence["status"] == "PASS":
        return []
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return [
        {
            "SchemaVersion": "2018-10-08",
            "Id": f"federal-data-residual/{evidence['case']['case_id']}",
            "ProductArn": f"arn:aws:securityhub:us-east-1:{AWS_ACCOUNT_ID}:product/{AWS_ACCOUNT_ID}/default",
            "GeneratorId": LAB_ID,
            "AwsAccountId": AWS_ACCOUNT_ID,
            "Types": ["Sensitive Data Identifications/PII/Federal Customer Data"],
            "CreatedAt": now,
            "UpdatedAt": now,
            "Severity": {"Label": "CRITICAL"},
            "Title": "Federal customer data residual after deletion case",
            "Description": (
                f"Case {evidence['case']['case_id']} tenant={evidence['case']['tenant_id']} "
                f"residuals={evidence['residual_hit_count']}. Fails KSI-SVC-RUD/PRR."
            ),
            "Compliance": {"Status": "FAILED"},
            "RecordState": "ACTIVE",
            "Resources": [
                {"Type": "Other", "Id": evidence["case"]["tenant_id"], "Partition": "aws", "Region": "us-east-1"}
            ],
        }
    ]


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        case = validate_case(event.get("case") or event)
    except ValueError as exc:
        return {"statusCode": 400, "body": json.dumps({"lab_id": LAB_ID, "status": "ERROR", "error": str(exc)})}

    stores = resolve_catalog(case.tenant_id, event.get("catalog"))
    live_actions = [purge_live_store(s) for s in stores if s.service != "backup"]
    backup_actions = purge_backups(case, stores)
    residuals = residual_scan(case.tenant_id, stores, event.get("simulate_residual_hits"))
    evidence = build_evidence(case, stores, live_actions, backup_actions, residuals)
    findings = to_asff(evidence)
    print(json.dumps({"status": evidence["status"], "residuals": evidence["residual_hit_count"], "case": case.case_id}))
    return {"statusCode": 200, "body": json.dumps(evidence), "findings": findings}
