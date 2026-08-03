"""Terraform DR Readiness & State-Backend Resilience.

Disaster recovery for Terraform-managed systems has two IaC-specific failure
modes that runtime backup checks (lab 12) miss:

  1. **State-backend resilience.** Terraform state is the control plane you
     recover *from* — you rebuild infrastructure by re-applying. If the state
     backend is a local file, or an S3 backend without versioning, encryption,
     cross-region replication, and locking, then a region or backend loss
     takes your ability to recover with it.
  2. **DR architecture parity.** The Terraform *code* must actually encode the
     DR posture the RTO/RPO demands: a designated recovery region, cross-region
     durability on critical data stores (replication / PITR / cross-region
     backup), backup plans, and failover routing.

This lab evaluates a DR-readiness descriptor derived from Terraform (a CI job
produces it from `terraform show -json` plus the backend config) and emits the
same fail-closed, assessor-ready assurance case as lab 16 — provenance bound to
the Terraform commit, a SHA-256 integrity manifest, and per-control mapping to
the real NIST CP-family assessment objectives.

This lab does NOT execute a failover — it validates that recovery is *possible*
from the declared IaC and a resilient state backend. Runtime restore-drill
outcomes are lab 12's job; the two are complementary.

Env contract: EVIDENCE_BUCKET, SNS_TOPIC_ARN, DESCRIPTOR_BUCKET (optional),
DESCRIPTOR_KEY (optional), FAIL_SEVERITY (critical|high|medium|low, default
high), RTO_TARGET_MINUTES, RPO_TARGET_MINUTES (DR-plan/ODP targets),
TERRAFORM_COMMIT, TERRAFORM_WORKSPACE, COLLECTOR_ROLE_ARN, LOG_LEVEL.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
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
    publish_alert,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "17-terraform-dr-readiness"
SCF_CONTROLS = ["BCD-01", "BCD-02", "BCD-11", "BCD-12", "CFG-01"]
FEDRAMP_KSI = ["KSI-CNA-EIS", "KSI-CNA-OFA", "KSI-RPL-ABO", "KSI-RPL-ARP", "KSI-RPL-RRO"]

logger = get_logger(LAB_ID)

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Assessor mapping for the assurance case: the real NIST 800-171 rev 3 and
# 800-53 rev 5 CP-family objectives these SCF controls crosswalk to (see
# scf-mapping.generated.json). Embedded so the handler exports standalone.
CONTROL_ASSESSMENT = {
    "BCD-01": {
        "title": "Business Continuity Management System (BCMS)",
        "claim": "A DR program is defined and the recovery architecture is declared in IaC.",
        "nist_800_171_r3": [],
        "nist_800_53_r5": ["CP-01", "CP-02", "CP-10", "IR-04(03)", "PM-08"],
        "odp_references": ["A.03.06.01.ODP[01]"],
    },
    "BCD-02": {
        "title": "Identify Critical Assets",
        "claim": "Critical data stores in scope for DR are identified with recovery objectives.",
        "nist_800_171_r3": [],
        "nist_800_53_r5": ["CP-02(08)"],
        "odp_references": ["A.03.06.01.ODP[02]"],
    },
    "BCD-11": {
        "title": "Data Backups",
        "claim": "Critical data has cross-region durability meeting the RPO target.",
        "nist_800_171_r3": ["03.08.09.a"],
        "nist_800_53_r5": ["CP-09", "SC-28(02)"],
        "odp_references": ["A.03.08.09.ODP[01]"],
    },
    "BCD-12": {
        "title": "Technology Assets, Applications and/or Services (TAAS) Recovery & Reconstitution",
        "claim": "Infrastructure can be reconstituted in the recovery region from IaC within the RTO target.",
        "nist_800_171_r3": [],
        "nist_800_53_r5": ["CP-10"],
        "odp_references": ["A.03.06.02.ODP[01]"],
    },
    "CFG-01": {
        "title": "Configuration Management Program",
        "claim": "The Terraform state backend is resilient, so recovery-by-reapply survives a region loss.",
        "nist_800_171_r3": ["03.04.01.a"],
        "nist_800_53_r5": ["CM-01", "CM-09"],
        "odp_references": ["A.03.04.01.ODP[01]"],
    },
}


@dataclass
class DataStore:
    address: str
    store_type: str
    critical: bool = True
    cross_region_replication: bool = False
    replication_target_region: str | None = None
    point_in_time_recovery: bool = False
    cross_region_backup: bool = False

    @classmethod
    def from_dict(cls, raw: Any) -> DataStore:
        if not isinstance(raw, dict):
            raise ValueError(f"data_store must be an object, got {type(raw).__name__}")
        address = str(raw.get("address") or "")
        if not address:
            raise ValueError("data_store requires an address")
        return cls(
            address=address,
            store_type=str(raw.get("store_type") or raw.get("type") or "unknown"),
            critical=bool(raw.get("critical", True)),
            cross_region_replication=bool(raw.get("cross_region_replication", False)),
            replication_target_region=raw.get("replication_target_region"),
            point_in_time_recovery=bool(raw.get("point_in_time_recovery", False)),
            cross_region_backup=bool(raw.get("cross_region_backup", False)),
        )

    def is_durable(self) -> bool:
        return self.cross_region_replication or (
            self.point_in_time_recovery and self.cross_region_backup
        )


@dataclass
class StateBackend:
    backend_type: str = "local"
    bucket: str | None = None
    region: str | None = None
    versioning: bool = False
    kms_encrypted: bool = False
    cross_region_replication: bool = False
    locking: bool = False
    lock_mechanism: str | None = None

    @classmethod
    def from_dict(cls, raw: Any) -> StateBackend:
        if not isinstance(raw, dict):
            raise ValueError(f"backend must be an object, got {type(raw).__name__}")
        return cls(
            backend_type=str(raw.get("backend_type") or raw.get("type") or "local"),
            bucket=raw.get("bucket"),
            region=raw.get("region"),
            versioning=bool(raw.get("versioning", False)),
            kms_encrypted=bool(raw.get("kms_encrypted", False)),
            cross_region_replication=bool(raw.get("cross_region_replication", False)),
            locking=bool(raw.get("locking", False)),
            lock_mechanism=raw.get("lock_mechanism"),
        )


@dataclass
class DrDescriptor:
    backend: StateBackend
    primary_region: str
    recovery_region: str | None
    data_stores: list[DataStore]
    failover_routing: bool = False
    declared_rto_minutes: int | None = None
    declared_rpo_minutes: int | None = None
    tags_scope: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Any) -> DrDescriptor:
        if not isinstance(raw, dict):
            raise ValueError(f"descriptor must be an object, got {type(raw).__name__}")
        stores = raw.get("data_stores") or []
        if not isinstance(stores, list):
            raise ValueError("data_stores must be a list")
        primary = str(raw.get("primary_region") or "")
        if not primary:
            raise ValueError("descriptor requires a primary_region")
        return cls(
            backend=StateBackend.from_dict(raw.get("backend") or {}),
            primary_region=primary,
            recovery_region=raw.get("recovery_region"),
            data_stores=[DataStore.from_dict(s) for s in stores],
            failover_routing=bool(raw.get("failover_routing", False)),
            declared_rto_minutes=raw.get("declared_rto_minutes"),
            declared_rpo_minutes=raw.get("declared_rpo_minutes"),
            tags_scope=[str(t) for t in (raw.get("tags_scope") or [])],
        )


def _finding(code: str, severity: str, detail: str, control: str) -> dict[str, Any]:
    return {"code": code, "severity": severity, "detail": detail, "scf_control": control}


def evaluate_backend(backend: StateBackend) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if backend.backend_type == "local":
        findings.append(_finding(
            "state-backend-local", "critical",
            "Terraform state is a local file — the IaC control plane is not recoverable "
            "after host/region loss. Use a remote, replicated, locking backend.",
            "CFG-01"))
        return findings  # nothing else is meaningful for a local backend
    if not backend.locking:
        findings.append(_finding(
            "state-backend-no-lock", "high",
            "State backend has no locking — concurrent applies during recovery can corrupt state "
            "(add a DynamoDB lock table or use a backend with native locking).",
            "CFG-01"))
    if not backend.versioning:
        findings.append(_finding(
            "state-backend-no-versioning", "high",
            "State bucket versioning is disabled — a bad apply cannot be rolled back.",
            "CFG-01"))
    if not backend.kms_encrypted:
        findings.append(_finding(
            "state-backend-unencrypted", "high",
            "State bucket is not KMS-encrypted — state can contain sensitive values.",
            "CFG-01"))
    if not backend.cross_region_replication:
        findings.append(_finding(
            "state-backend-no-replication", "high",
            "State bucket is not cross-region replicated — a region loss takes the backend "
            "(and the ability to recover) with it.",
            "CFG-01"))
    return findings


def evaluate_architecture(desc: DrDescriptor) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not desc.recovery_region:
        findings.append(_finding(
            "no-recovery-region", "high",
            "No recovery region is designated — reconstitution has no target.",
            "BCD-12"))
    elif desc.recovery_region == desc.primary_region:
        findings.append(_finding(
            "recovery-region-equals-primary", "high",
            f"Recovery region equals the primary region ({desc.primary_region}) — no geographic "
            "separation for DR.",
            "BCD-12"))

    critical_stores = [s for s in desc.data_stores if s.critical]
    if not critical_stores:
        findings.append(_finding(
            "no-critical-stores-identified", "medium",
            "No critical data stores are identified for DR scope — cannot assert RPO coverage.",
            "BCD-02"))
    for store in critical_stores:
        if not store.is_durable():
            # Durability = cross-region replication, OR PITR + a cross-region
            # backup. A store meeting either survives a region loss (RPO); one
            # meeting neither cannot.
            findings.append(_finding(
                "store-not-cross-region-durable", "critical",
                f"Critical store {store.address} ({store.store_type}) has no cross-region "
                "durability (replication, or PITR + cross-region backup) — RPO cannot be met "
                "on region loss.",
                "BCD-11"))

    if not desc.failover_routing:
        severity = "high" if (desc.declared_rto_minutes or 9999) <= 60 else "medium"
        findings.append(_finding(
            "no-failover-routing", severity,
            "No failover routing declared (e.g. Route53 health-checked failover) — recovery "
            "requires manual redirection, extending RTO.",
            "BCD-12"))
    return findings


def evaluate_objectives(
    desc: DrDescriptor, rto_target: int | None, rpo_target: int | None
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if rto_target is not None:
        if desc.declared_rto_minutes is None:
            findings.append(_finding(
                "rto-not-declared", "medium",
                f"DR plan targets RTO {rto_target} min but the descriptor declares no RTO "
                "capability to compare.",
                "BCD-01"))
        elif desc.declared_rto_minutes > rto_target:
            findings.append(_finding(
                "rto-target-unmet", "high",
                f"Declared RTO {desc.declared_rto_minutes} min exceeds the target {rto_target} min.",
                "BCD-12"))
    if rpo_target is not None:
        if desc.declared_rpo_minutes is None:
            findings.append(_finding(
                "rpo-not-declared", "medium",
                f"DR plan targets RPO {rpo_target} min but the descriptor declares no RPO "
                "capability to compare.",
                "BCD-01"))
        elif desc.declared_rpo_minutes > rpo_target:
            findings.append(_finding(
                "rpo-target-unmet", "high",
                f"Declared RPO {desc.declared_rpo_minutes} min exceeds the target {rpo_target} min.",
                "BCD-11"))
    return findings


def build_evidence(
    desc: DrDescriptor,
    findings: list[dict[str, Any]],
    *,
    fail_severity: str,
    rto_target: int | None,
    rpo_target: int | None,
    data_source: str,
    descriptor_ref: str,
) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
    threshold = SEVERITY_ORDER[fail_severity]
    actionable = [f for f in findings if SEVERITY_ORDER[f["severity"]] >= threshold]
    status = Status.FAIL if actionable else Status.PASS
    return {
        "lab_id": LAB_ID,
        "checked_at": utc_now().isoformat(),
        "status": status.value,
        "data_source": data_source,
        "descriptor_reference": descriptor_ref,
        "primary_region": desc.primary_region,
        "recovery_region": desc.recovery_region,
        "state_backend_type": desc.backend.backend_type,
        "critical_store_count": sum(1 for s in desc.data_stores if s.critical),
        "findings": findings,
        "finding_count": len(findings),
        "findings_by_severity": by_severity,
        "actionable_findings": actionable,
        "actionable_finding_count": len(actionable),
        "recovery_objectives": {
            "rto_target_minutes": rto_target,
            "rpo_target_minutes": rpo_target,
            "declared_rto_minutes": desc.declared_rto_minutes,
            "declared_rpo_minutes": desc.declared_rpo_minutes,
        },
        "policy": {"fail_severity": fail_severity},
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "methodology": {
            "state_backend": "remote + versioned + KMS + cross-region replicated + locking",
            "architecture_parity": "recovery region + cross-region durable critical stores + backup + failover routing",
            "objective_alignment": "declared RTO/RPO vs DR-plan targets (env RTO_TARGET_MINUTES/RPO_TARGET_MINUTES)",
            "producer": "CI derives the descriptor from terraform show -json + backend config",
            "persistent_cadence": "daily EventBridge schedule",
        },
    }


def build_provenance(context: Any, runtime: RuntimeContext, event: dict[str, Any], ref: str) -> dict[str, Any]:
    collector_role = (
        os.environ.get("COLLECTOR_ROLE_ARN", "").strip()
        or f"arn:{runtime.partition}:lambda:{runtime.region}:{runtime.account_id}:function:{LAB_ID}"
    )
    return {
        "collected_at": utc_now().isoformat(),
        "collector_role": collector_role,
        "account_id": runtime.account_id,
        "region": runtime.region,
        "partition": runtime.partition,
        "aws_request_id": getattr(context, "aws_request_id", None),
        "terraform_commit": str(
            event.get("terraform_commit") or os.environ.get("TERRAFORM_COMMIT", "") or "unknown"
        ),
        "terraform_workspace": str(
            event.get("terraform_workspace") or os.environ.get("TERRAFORM_WORKSPACE", "") or "default"
        ),
        "descriptor_reference": ref,
        "evidence_manifest_sha256": None,
    }


def build_assurance_case(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    failing_controls = {f["scf_control"] for f in evidence["actionable_findings"]}
    case = []
    for control in SCF_CONTROLS:
        meta = CONTROL_ASSESSMENT[control]
        satisfied = control not in failing_controls
        case.append({
            "scf_control": control,
            "title": meta["title"],
            "claim": meta["claim"],
            "status": "SATISFIED" if satisfied else "OTHER-THAN-SATISFIED",
            "nist_800_171_r3_objectives": meta["nist_800_171_r3"],
            "nist_800_53_r5_objectives": meta["nist_800_53_r5"],
            "odp_references": meta["odp_references"],
            "evidence": {
                "descriptor_reference": evidence["descriptor_reference"],
                "findings": [f for f in evidence["findings"] if f["scf_control"] == control],
                "artifact": "self (this evidence object)",
            },
        })
    return case


def evidence_manifest_sha256(evidence: dict[str, Any]) -> str:
    payload = {k: v for k, v in evidence.items() if k not in ("evidence_uri",)}
    payload = json.loads(json.dumps(payload, default=str))
    if payload.get("provenance", {}).get("evidence_manifest_sha256") is not None:
        payload["provenance"] = dict(payload["provenance"])
        payload["provenance"]["evidence_manifest_sha256"] = None
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_descriptor(event: dict[str, Any], s3_client: Any) -> tuple[dict[str, Any], str, str]:
    if isinstance(event.get("descriptor"), dict):
        return event["descriptor"], "event", "event.descriptor"
    bucket = os.environ.get("DESCRIPTOR_BUCKET", "").strip()
    key = (event.get("descriptor_key") or os.environ.get("DESCRIPTOR_KEY", "")).strip()
    if not bucket or not key:
        raise ConfigError(
            "no DR descriptor supplied — set DESCRIPTOR_BUCKET/DESCRIPTOR_KEY (CI derives it "
            "from terraform show -json + backend config) or pass event.descriptor"
        )
    if s3_client is None:  # pragma: no cover - AWS only
        import boto3

        s3_client = boto3.client("s3")
    body = s3_client.get_object(Bucket=bucket, Key=key)["Body"].read()
    return json.loads(body), "s3", f"s3://{bucket}/{key}"


def _simulation_descriptor() -> dict[str, Any]:
    """Deterministic demo: a resilient state backend but a critical store with
    no cross-region durability and no failover routing -> FAIL."""
    return {
        "backend": {
            "backend_type": "s3", "bucket": "tf-state", "region": "us-east-1",
            "versioning": True, "kms_encrypted": True, "cross_region_replication": True,
            "locking": True, "lock_mechanism": "dynamodb",
        },
        "primary_region": "us-east-1",
        "recovery_region": "us-west-2",
        "data_stores": [
            {"address": "aws_s3_bucket.cui", "store_type": "aws_s3_bucket", "critical": True,
             "cross_region_replication": False, "point_in_time_recovery": False,
             "cross_region_backup": False},
            {"address": "aws_dynamodb_table.sessions", "store_type": "aws_dynamodb_table",
             "critical": True, "cross_region_replication": True},
        ],
        "failover_routing": False,
        "declared_rto_minutes": 120,
        "declared_rpo_minutes": 60,
    }


def handler(
    event: dict[str, Any],
    context: Any,
    s3_client: Any = None,
    sns_client: Any = None,
    securityhub_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        runtime = RuntimeContext.from_lambda(context)
        fail_severity = os.environ.get("FAIL_SEVERITY", "high").strip().lower()
        if fail_severity not in SEVERITY_ORDER:
            raise ConfigError(
                f"FAIL_SEVERITY must be one of {sorted(SEVERITY_ORDER)}, got {fail_severity!r}"
            )
        rto_target = get_int_env("RTO_TARGET_MINUTES", default=0) or None
        rpo_target = get_int_env("RPO_TARGET_MINUTES", default=0) or None

        if simulation_requested(event):
            raw, data_source, ref = _simulation_descriptor(), "simulation", "simulation"
        else:
            raw, data_source, ref = load_descriptor(event, s3_client)

        try:
            desc = DrDescriptor.from_dict(raw)
        except ValueError as exc:
            logger.error("invalid descriptor", extra={"extra_fields": {"error": str(exc)}})
            return respond(Status.ERROR, {"lab_id": LAB_ID, "error": str(exc), "run_id": run_id})

        findings = (
            evaluate_backend(desc.backend)
            + evaluate_architecture(desc)
            + evaluate_objectives(desc, rto_target, rpo_target)
        )
        evidence = build_evidence(
            desc, findings,
            fail_severity=fail_severity, rto_target=rto_target, rpo_target=rpo_target,
            data_source=data_source, descriptor_ref=ref,
        )
        status = Status(evidence["status"])

        evidence["provenance"] = build_provenance(context, runtime, event, ref)
        evidence["assurance_case"] = build_assurance_case(evidence)
        evidence["provenance"]["evidence_manifest_sha256"] = evidence_manifest_sha256(evidence)

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is Status.FAIL:
            emitter = AsffEmitter(LAB_ID, runtime, client=securityhub_client)
            emitter.emit([emitter.build_finding(
                finding_id=f"dr-readiness/{run_id}",
                title="Terraform-managed system is not disaster-recovery ready",
                description=(
                    f"{evidence['actionable_finding_count']} DR-readiness gap(s) at or above "
                    f"{fail_severity} across the state backend and DR architecture. "
                    "Recovery-by-reapply is not assured."
                ),
                severity="HIGH",
                resource_type="Other",
                resource_id=f"account/{runtime.account_id}/terraform-dr",
                status=status,
            )])
            publish_alert(
                LAB_ID, status,
                f"{evidence['actionable_finding_count']} actionable DR-readiness gap(s) "
                f"(>= {fail_severity}); {evidence['finding_count']} total",
                sns_client=sns_client,
            )
        logger.info(
            "dr readiness check complete",
            extra={"extra_fields": {
                "run_id": run_id, "status": status.value,
                "findings": evidence["finding_count"],
                "actionable": evidence["actionable_finding_count"],
                "data_source": data_source,
            }},
        )
        return respond(status, evidence)
    except ConfigError as exc:
        logger.error("configuration error", extra={"extra_fields": {"run_id": run_id, "error": str(exc)}})
        return respond(Status.CONFIG_ERROR, {"lab_id": LAB_ID, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001 - fail closed, never crash the invocation
        logger.exception("unhandled error")
        return respond(Status.ERROR, {"lab_id": LAB_ID, "error": str(exc), "run_id": run_id})
