"""Federal customer data deletion & residual-data proof.

FedRAMP CR26 Class C:
  - KSI-SVC-RUD: remove unwanted federal customer data promptly (incl. backups when appropriate)
  - KSI-SVC-PRR: after changes, review/remove residual elements that harm federal data CIA

Flow:
  1. Ingest deletion case (tenant_id / agency_id / data classes)
  2. Resolve catalog of live stores + backup vaults for that tenant (event-supplied;
     an empty catalog outside simulation is CONFIG_ERROR — never a demo footprint)
  3. Purge live objects (S3 prefixes, DynamoDB tenant partitions) and tenant-tagged
     backup recovery points — ONLY when ENABLE_PURGE=true; otherwise DRY_RUN
  4. Residual scan with real API calls (S3 versions included, DynamoDB query,
     Backup recovery-point tags)
  5. Emit evidence JSON + Security Hub ASFF on FAIL

Verdict semantics (fail closed):
  - PASS requires a real residual scan across every cataloged store with zero
    hits, no failed purge action, and no unverifiable store.
  - Stores this lab cannot verify programmatically (rds, opensearch) produce an
    "unverified" residual entry → FAIL until a manual check is recorded.
  - ``simulate_residual_hits`` is honored only in ``{"mode": "simulation"}``
    events and the evidence is stamped ``data_source: simulation``.
  - Placeholder/dry-run purge states never count as completed deletion; if data
    is still present the scan reports it.

Env contract: EVIDENCE_BUCKET, SNS_TOPIC_ARN, TENANT_TAG_KEY (default
federal_tenant_id), ENABLE_PURGE (default false → dry run),
REQUIRE_BACKUP_PURGE (default true), CASE_TABLE (optional case-of-record),
LOG_LEVEL.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from lab_common import (
    AsffEmitter,
    ConfigError,
    EvidenceWriter,
    RuntimeContext,
    Status,
    get_bool_env,
    get_logger,
    new_run_id,
    publish_alert,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "11-federal-data-deletion-residual"
SCF_CONTROLS = ["DCH-01", "DCH-09", "DCH-06", "BCD-11", "CRY-05", "CLD-01"]
FEDRAMP_KSI = ["KSI-SVC-RUD", "KSI-SVC-PRR", "KSI-SVC-SIN", "KSI-AFR-PVL"]

logger = get_logger(LAB_ID)

VERIFIABLE_SERVICES = {"s3", "dynamodb", "backup"}
MANUAL_SERVICES = {"rds", "opensearch"}
_TENANT_RE = re.compile(r"^[A-Za-z0-9_.:-]{3,128}$")


@dataclass
class DataStoreRef:
    service: str  # s3 | dynamodb | rds | opensearch | backup
    arn_or_name: str
    tenant_id: str
    contains_federal_data: bool = True
    backup_vault: str | None = None
    tenant_key_attribute: str = "tenant_id"  # DynamoDB partition-key attribute

    @classmethod
    def from_dict(cls, raw: dict[str, Any], tenant_id: str) -> DataStoreRef:
        service = str(raw.get("service") or "")
        if service not in VERIFIABLE_SERVICES | MANUAL_SERVICES:
            raise ValueError(f"unsupported store service: {service!r}")
        arn_or_name = str(raw.get("arn_or_name") or "")
        if not arn_or_name:
            raise ValueError("store arn_or_name is required")
        return cls(
            service=service,
            arn_or_name=arn_or_name,
            tenant_id=tenant_id,
            contains_federal_data=bool(raw.get("contains_federal_data", True)),
            backup_vault=raw.get("backup_vault"),
            tenant_key_attribute=str(raw.get("tenant_key_attribute") or "tenant_id"),
        )


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
    status: str  # OK | DRY_RUN | SKIPPED | FAILED | MANUAL_REQUIRED
    detail: str


@dataclass
class ResidualHit:
    store: str
    locator: str
    confidence: str  # confirmed | unverified

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ResidualHit:
        return cls(
            store=str(raw.get("store") or "unknown"),
            locator=str(raw.get("locator") or "unknown"),
            confidence=str(raw.get("confidence") or "confirmed"),
        )


def deterministic_case_id(tenant_id: str, requested_at: str, reason: str) -> str:
    """Stable case id — Step Functions retries converge on one case instead of
    minting a new case per attempt (previous behavior used a wall-clock int)."""
    digest = hashlib.sha256(f"{tenant_id}|{requested_at}|{reason}".encode()).hexdigest()[:12]
    return f"case-{tenant_id}-{digest}"


def validate_case(raw: dict[str, Any]) -> DeletionCase:
    tenant = str(raw.get("tenant_id") or "").strip()
    if not _TENANT_RE.match(tenant):
        raise ValueError("tenant_id is required and must be a safe identifier")
    reason = str(raw.get("reason") or "customer_request")
    if reason not in {"offboarding", "spill", "customer_request"}:
        raise ValueError("reason must be offboarding|spill|customer_request")
    agency = str(raw.get("agency_id") or "unknown-agency")
    if len(agency) > 128:
        raise ValueError("agency_id too long")
    requested_at = str(raw.get("requested_at") or utc_now().isoformat())
    case_id = str(raw.get("case_id") or deterministic_case_id(tenant, requested_at, reason))
    if not re.match(r"^[A-Za-z0-9_.:-]{3,160}$", case_id):
        raise ValueError("case_id must be a safe identifier")
    return DeletionCase(
        case_id=case_id,
        agency_id=agency,
        tenant_id=tenant,
        reason=reason,
        requested_at=requested_at,
        include_backups=bool(raw.get("include_backups", True)),
        data_classes=[str(c) for c in (raw.get("data_classes") or ["CUI", "federal_customer"])],
    )


def resolve_catalog(
    tenant_id: str, event_catalog: list[dict[str, Any]] | None, simulated: bool
) -> list[DataStoreRef]:
    """Event-supplied catalog only. The demo footprint exists solely for
    simulation mode — a live run with no catalog is a configuration gap."""
    if event_catalog:
        return [
            DataStoreRef.from_dict(i, tenant_id)
            for i in event_catalog
            if i.get("tenant_id", tenant_id) == tenant_id
        ]
    if simulated:
        return [
            DataStoreRef("s3", f"s3://federal-app-data/{tenant_id}/", tenant_id, True, "federal-vault"),
            DataStoreRef("dynamodb", "TenantData", tenant_id, True, "federal-vault"),
            DataStoreRef("backup", "federal-vault", tenant_id, True, "federal-vault"),
        ]
    raise ConfigError(
        "no data-store catalog supplied for tenant; wire the inventory feed "
        "(labs 13/04) or pass event.catalog"
    )


def _parse_s3_ref(ref: str) -> tuple[str, str]:
    if not ref.startswith("s3://"):
        raise ValueError(f"S3 store must be s3://bucket/prefix, got {ref!r}")
    without = ref[len("s3://"):]
    bucket, _, prefix = without.partition("/")
    if not bucket:
        raise ValueError(f"S3 store missing bucket: {ref!r}")
    return bucket, prefix


def _table_name(arn_or_name: str) -> str:
    return arn_or_name.rsplit("/", 1)[-1] if "table/" in arn_or_name else arn_or_name


# --------------------------------------------------------------------------
# Purge (live only when ENABLE_PURGE=true; otherwise DRY_RUN reporting)
# --------------------------------------------------------------------------

def purge_s3_prefix(store: DataStoreRef, enable: bool, s3_client: Any) -> PurgeAction:
    bucket, prefix = _parse_s3_ref(store.arn_or_name)
    if not enable:
        return PurgeAction(store.arn_or_name, "purge_s3", "DRY_RUN",
                           f"would delete all versions under s3://{bucket}/{prefix}")
    deleted = 0
    paginator = s3_client.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        objects = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for group in ("Versions", "DeleteMarkers")
            for v in page.get(group, [])
        ]
        for start in range(0, len(objects), 1000):
            batch = objects[start:start + 1000]
            if batch:
                s3_client.delete_objects(Bucket=bucket, Delete={"Objects": batch, "Quiet": True})
                deleted += len(batch)
    return PurgeAction(store.arn_or_name, "purge_s3", "OK",
                       f"deleted {deleted} object versions under s3://{bucket}/{prefix}")


def purge_dynamodb_partition(store: DataStoreRef, enable: bool, dynamodb_client: Any) -> PurgeAction:
    table = _table_name(store.arn_or_name)
    if not enable:
        return PurgeAction(store.arn_or_name, "purge_dynamodb", "DRY_RUN",
                           f"would delete items where {store.tenant_key_attribute}={store.tenant_id}")
    schema = dynamodb_client.describe_table(TableName=table)["Table"]["KeySchema"]
    key_names = [k["AttributeName"] for k in schema]
    deleted = 0
    paginator = dynamodb_client.get_paginator("query")
    for page in paginator.paginate(
        TableName=table,
        KeyConditionExpression="#pk = :tenant",
        ExpressionAttributeNames={"#pk": store.tenant_key_attribute},
        ExpressionAttributeValues={":tenant": {"S": store.tenant_id}},
    ):
        items = page.get("Items", [])
        for start in range(0, len(items), 25):
            batch = items[start:start + 25]
            if batch:
                dynamodb_client.batch_write_item(RequestItems={table: [
                    {"DeleteRequest": {"Key": {k: item[k] for k in key_names}}}
                    for item in batch
                ]})
                deleted += len(batch)
    return PurgeAction(store.arn_or_name, "purge_dynamodb", "OK",
                       f"deleted {deleted} items for tenant {store.tenant_id}")


def _tenant_recovery_points(
    vault: str, tenant_id: str, tenant_tag_key: str, backup_client: Any
) -> list[str]:
    arns: list[str] = []
    paginator = backup_client.get_paginator("list_recovery_points_by_backup_vault")
    for page in paginator.paginate(BackupVaultName=vault):
        for point in page.get("RecoveryPoints", []):
            arn = point.get("RecoveryPointArn", "")
            if not arn:
                continue
            tags = backup_client.list_tags(ResourceArn=arn).get("Tags", {})
            if tags.get(tenant_tag_key) == tenant_id:
                arns.append(arn)
    return arns


def purge_backups(
    case: DeletionCase,
    stores: list[DataStoreRef],
    *,
    enable: bool,
    require_backup_purge: bool,
    tenant_tag_key: str,
    backup_client: Any,
) -> list[PurgeAction]:
    """Backups are purged when the case asks for it OR policy requires it
    (REQUIRE_BACKUP_PURGE is a policy floor — a case cannot opt out of it)."""
    if not case.include_backups and not require_backup_purge:
        return [PurgeAction("backup", "skip", "SKIPPED", "include_backups=false and policy allows skip")]
    vaults = sorted({s.backup_vault for s in stores if s.backup_vault})
    if not vaults:
        return [PurgeAction("backup", "verify", "FAILED",
                            "no backup vault mapped for tenant stores — cannot attest backup purge")]
    actions = []
    for vault in vaults:
        points = _tenant_recovery_points(vault, case.tenant_id, tenant_tag_key, backup_client)
        if not enable:
            actions.append(PurgeAction(vault, "expire_recovery_points", "DRY_RUN",
                                       f"would delete {len(points)} tenant-tagged recovery points"))
            continue
        for arn in points:
            backup_client.delete_recovery_point(BackupVaultName=vault, RecoveryPointArn=arn)
        actions.append(PurgeAction(vault, "expire_recovery_points", "OK",
                                   f"deleted {len(points)} tenant-tagged recovery points"))
    return actions


# --------------------------------------------------------------------------
# Residual scan — real reads; this is what PASS hangs on
# --------------------------------------------------------------------------

def residual_scan(
    tenant_id: str,
    stores: list[DataStoreRef],
    *,
    tenant_tag_key: str,
    s3_client: Any,
    dynamodb_client: Any,
    backup_client: Any,
) -> list[ResidualHit]:
    hits: list[ResidualHit] = []
    for store in stores:
        if not store.contains_federal_data:
            continue
        if store.service == "s3":
            bucket, prefix = _parse_s3_ref(store.arn_or_name)
            paginator = s3_client.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                for group in ("Versions", "DeleteMarkers"):
                    for version in page.get(group, []):
                        hits.append(ResidualHit(
                            store.arn_or_name,
                            f"s3://{bucket}/{version['Key']}@{version.get('VersionId', 'null')}",
                            "confirmed",
                        ))
        elif store.service == "dynamodb":
            table = _table_name(store.arn_or_name)
            paginator = dynamodb_client.get_paginator("query")
            count = 0
            for page in paginator.paginate(
                TableName=table,
                KeyConditionExpression="#pk = :tenant",
                ExpressionAttributeNames={"#pk": store.tenant_key_attribute},
                ExpressionAttributeValues={":tenant": {"S": tenant_id}},
                Select="COUNT",
            ):
                count += int(page.get("Count", 0))
            if count:
                hits.append(ResidualHit(store.arn_or_name, f"{count} items for tenant", "confirmed"))
        elif store.service == "backup":
            vault = store.backup_vault or store.arn_or_name
            for arn in _tenant_recovery_points(vault, tenant_id, tenant_tag_key, backup_client):
                hits.append(ResidualHit(vault, arn, "confirmed"))
        else:  # rds / opensearch — cannot verify programmatically here
            hits.append(ResidualHit(
                store.arn_or_name,
                f"{store.service} store requires a recorded manual residual check",
                "unverified",
            ))
    return hits


def build_evidence(
    case: DeletionCase,
    stores: list[DataStoreRef],
    live_actions: list[PurgeAction],
    backup_actions: list[PurgeAction],
    residuals: list[ResidualHit],
    *,
    execution_mode: str,
    data_source: str,
    require_backup_purge: bool,
    tenant_tag_key: str,
) -> dict[str, Any]:
    purge_failed = any(a.status == "FAILED" for a in live_actions + backup_actions)
    status = Status.FAIL if residuals or purge_failed else Status.PASS
    return {
        "lab_id": LAB_ID,
        "checked_at": utc_now().isoformat(),
        "status": status.value,
        "data_source": data_source,
        "execution_mode": execution_mode,  # dry_run | live
        "case": asdict(case),
        "catalog_count": len(stores),
        "catalog": [asdict(s) for s in stores],
        "live_purge_actions": [asdict(a) for a in live_actions],
        "backup_purge_actions": [asdict(a) for a in backup_actions],
        "residual_hits": [asdict(h) for h in residuals],
        "residual_hit_count": len(residuals),
        "policy": {
            "require_backup_purge": require_backup_purge,
            "tenant_tag_key": tenant_tag_key,
            "enable_purge": execution_mode == "live",
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
            "all_stores_verified": not any(h.confidence == "unverified" for h in residuals),
            "purge_executed": execution_mode == "live" and not purge_failed,
            "evidence_retained_days_min": 365,
        },
    }


def record_case(evidence: dict[str, Any], case_table: str, dynamodb_client: Any) -> None:
    dynamodb_client.put_item(
        TableName=case_table,
        Item={
            "case_id": {"S": evidence["case"]["case_id"]},
            "updated_at": {"S": evidence["checked_at"]},
            "tenant_id": {"S": evidence["case"]["tenant_id"]},
            "status": {"S": evidence["status"]},
            "residual_hit_count": {"N": str(evidence["residual_hit_count"])},
            "execution_mode": {"S": evidence["execution_mode"]},
        },
    )


def handler(
    event: dict[str, Any],
    context: Any,
    s3_client: Any = None,
    dynamodb_client: Any = None,
    backup_client: Any = None,
    securityhub_client: Any = None,
    sns_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        runtime = RuntimeContext.from_lambda(context)
        simulated = simulation_requested(event)
        enable_purge = get_bool_env("ENABLE_PURGE", default=False) and not simulated
        require_backup_purge = get_bool_env("REQUIRE_BACKUP_PURGE", default=True)
        tenant_tag_key = os.environ.get("TENANT_TAG_KEY", "federal_tenant_id")

        try:
            case = validate_case(event.get("case") or event)
            stores = resolve_catalog(case.tenant_id, event.get("catalog"), simulated)
        except ValueError as exc:
            logger.error("invalid deletion case", extra={"extra_fields": {"error": str(exc)}})
            return respond(Status.ERROR, {"lab_id": LAB_ID, "error": str(exc), "run_id": run_id})

        if s3_client is None or dynamodb_client is None or backup_client is None:  # pragma: no cover
            import boto3

            s3_client = s3_client or boto3.client("s3")
            dynamodb_client = dynamodb_client or boto3.client("dynamodb")
            backup_client = backup_client or boto3.client("backup")

        live_stores = [s for s in stores if s.service in {"s3", "dynamodb"}]
        manual_stores = [s for s in stores if s.service in MANUAL_SERVICES]
        live_actions: list[PurgeAction] = []
        for store in live_stores:
            if not store.contains_federal_data:
                live_actions.append(PurgeAction(store.arn_or_name, "skip", "SKIPPED", "not marked federal"))
            elif store.service == "s3":
                live_actions.append(purge_s3_prefix(store, enable_purge, s3_client))
            else:
                live_actions.append(purge_dynamodb_partition(store, enable_purge, dynamodb_client))
        live_actions.extend(
            PurgeAction(s.arn_or_name, f"purge_{s.service}", "MANUAL_REQUIRED",
                        "programmatic purge not supported for this service; record manual purge")
            for s in manual_stores
        )
        backup_actions = purge_backups(
            case, stores,
            enable=enable_purge, require_backup_purge=require_backup_purge,
            tenant_tag_key=tenant_tag_key, backup_client=backup_client,
        )

        if simulated:
            raw_hits = event.get("simulate_residual_hits") or []
            residuals = [ResidualHit.from_dict(h) for h in raw_hits]
            data_source = "simulation"
        else:
            # A live event may NOT inject scan results — the scan is the proof.
            residuals = residual_scan(
                case.tenant_id, stores,
                tenant_tag_key=tenant_tag_key,
                s3_client=s3_client, dynamodb_client=dynamodb_client,
                backup_client=backup_client,
            )
            data_source = "aws-api"

        evidence = build_evidence(
            case, stores, live_actions, backup_actions, residuals,
            execution_mode="live" if enable_purge else "dry_run",
            data_source=data_source,
            require_backup_purge=require_backup_purge,
            tenant_tag_key=tenant_tag_key,
        )
        status = Status(evidence["status"])

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(evidence, run_id)

        case_table = os.environ.get("CASE_TABLE", "")
        if case_table:
            record_case(evidence, case_table, dynamodb_client)

        if status is not Status.PASS:
            emitter = AsffEmitter(LAB_ID, runtime, client=securityhub_client)
            emitter.emit([emitter.build_finding(
                finding_id=f"residual/{case.case_id}",
                title="Federal customer data residual after deletion case",
                description=(
                    f"Case {case.case_id} tenant={case.tenant_id} "
                    f"residuals={evidence['residual_hit_count']} "
                    f"mode={evidence['execution_mode']}. Fails KSI-SVC-RUD/PRR."
                ),
                severity="CRITICAL",
                resource_type="Other",
                resource_id=f"tenant/{case.tenant_id}",
                status=status,
            )])
            publish_alert(
                LAB_ID, status,
                f"Deletion case {case.case_id}: {evidence['residual_hit_count']} residual hit(s), "
                f"mode={evidence['execution_mode']}",
                sns_client=sns_client,
            )

        logger.info("deletion case evaluated", extra={"extra_fields": {
            "run_id": run_id, "case_id": case.case_id, "status": status.value,
            "residuals": evidence["residual_hit_count"], "mode": evidence["execution_mode"],
        }})
        return respond(status, evidence)
    except ConfigError as exc:
        logger.error("configuration error", extra={"extra_fields": {"run_id": run_id, "error": str(exc)}})
        return respond(Status.CONFIG_ERROR, {"lab_id": LAB_ID, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001 - fail closed, never crash the invocation
        logger.exception("unhandled error")
        return respond(Status.ERROR, {"lab_id": LAB_ID, "error": str(exc), "run_id": run_id})
