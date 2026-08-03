"""Terraform State Drift Detection & Remediation Governance.

Out-of-band changes to Terraform-managed infrastructure (console edits,
scripts, other tooling) silently break the declared baseline. This lab
evaluates a machine-readable Terraform plan and produces compliance evidence.

Division of labor (honest about what runs where):
  * A CI job runs `terraform plan -refresh-only -out tfplan` then
    `terraform show -json tfplan` and drops the JSON in the plan-artifact
    bucket (Terraform needs its binary + cloud credentials — not the Lambda).
  * This Lambda reads that plan JSON, classifies each drifted resource by
    severity, applies an ignore list for expected drift, and emits
    fail-closed evidence with Security Hub findings and SNS alerts.

The severity model, the `.tfdriftignore`-style ignore patterns, and the
resource/attribute classification follow the tfdrift tool's approach
(https://github.com/sudarshan8417/tfdrift), adapted to this portfolio's
evidence contract.

Drift signal: Terraform's dedicated top-level ``resource_drift`` array
(populated by a refresh) is authoritative; ``resource_changes`` with
non-no-op actions is the fallback for older plan formats.

Auto-remediation is deliberately NOT performed here — remediation belongs in
a gated CI apply with approval (tfdrift's safety model). This lab reports and
alerts; ``REMEDIATION_MODE`` records the intended posture in the evidence.

Env contract: EVIDENCE_BUCKET, SNS_TOPIC_ARN, PLAN_BUCKET (optional; where CI
drops plan JSON), PLAN_KEY (optional), FAIL_SEVERITY (critical|high|medium|low,
default high), DRIFT_IGNORE (comma-separated glob patterns for expected drift),
REMEDIATION_MODE (report|dry_run, default report), LOG_LEVEL.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from typing import Any

from lab_common import (
    AsffEmitter,
    ConfigError,
    EvidenceWriter,
    RuntimeContext,
    Status,
    get_csv_env,
    get_logger,
    new_run_id,
    publish_alert,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "16-terraform-drift-detection"
SCF_CONTROLS = ["CFG-01", "CFG-02", "CPL-01", "MON-01", "CHG-02"]
FEDRAMP_KSI = ["KSI-AFR-PVL", "KSI-CNA-EIS", "KSI-CMT-RMV", "KSI-MLA-EVC"]

# Assessment mapping for the assessor-ready assurance case. Objective IDs are
# the real NIST 800-171 rev 3 (800-171A) and 800-53 rev 5 assessment
# objectives this lab's SCF controls crosswalk to (see scf-mapping.generated.json);
# ODP references point at the shipped governance/odp-register.yaml. Embedded so
# the handler stays self-contained (the lab exports standalone).
CONTROL_ASSESSMENT = {
    "CFG-01": {
        "title": "Configuration Management Program",
        "claim": "A Terraform baseline configuration is defined, reviewed, and enforced.",
        "nist_800_171_r3": ["03.04.01.a"],
        "nist_800_53_r5": ["CM-01", "CM-09"],
        "odp_references": ["A.03.04.01.ODP[01]"],
    },
    "CFG-02": {
        "title": "Secure Baseline Configurations",
        "claim": "Deployed resources conform to the approved secure baseline; drift is detected.",
        "nist_800_171_r3": ["03.04.01.a", "03.04.02.a"],
        "nist_800_53_r5": ["CM-02", "CM-06"],
        "odp_references": ["A.03.04.02.ODP[01]"],
    },
    "CPL-01": {
        "title": "Statutory, Regulatory & Contractual Compliance",
        "claim": "Configuration state is continuously evaluated against compliance requirements.",
        "nist_800_171_r3": ["03.04.11.a", "03.12.01"],
        "nist_800_53_r5": ["PL-01", "PM-08"],
        "odp_references": [],
    },
    "MON-01": {
        "title": "Continuous Monitoring",
        "claim": "Drift is monitored on a defined cadence with recorded evidence.",
        "nist_800_171_r3": ["03.03.01.a", "03.12.03", "03.14.06.a"],
        "nist_800_53_r5": ["AU-01", "PM-31", "SI-04"],
        "odp_references": ["A.03.12.03.ODP[01]"],
    },
    "CHG-02": {
        "title": "Configuration Change Control",
        "claim": "Managed infrastructure changes only through the controlled Terraform workflow; out-of-band change is flagged.",
        "nist_800_171_r3": ["03.04.02.b", "03.04.03.a", "03.04.03.b", "03.04.03.c"],
        "nist_800_53_r5": ["CM-03", "SA-08(31)"],
        "odp_references": ["A.03.04.03.ODP[01]"],
    },
}

logger = get_logger(LAB_ID)

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# tfdrift-style default classification by resource type + attribute. A CI
# deployment overrides via .tfdrift.yml; here the map is the fail-safe default.
# Address globs match "<resource_type>.<name>" or "<resource_type>.<name>.<attr>".
CRITICAL_PATTERNS = (
    "aws_security_group*",
    "aws_security_group_rule*",
    "*.ingress*",
    "*.egress*",
    "aws_iam_policy*",
    "aws_iam_role_policy*",
    "*.assume_role_policy*",
    "aws_s3_bucket_policy*",
    "aws_kms_key*",
    "*.policy*",
    "aws_iam_*_key*",
)
HIGH_PATTERNS = (
    "aws_iam_role*",
    "aws_iam_user*",
    "*.instance_type*",
    "aws_db_instance*",
    "aws_lambda_function*",
    "*.publicly_accessible*",
)
LOW_PATTERNS = (
    "*.tags*",
    "*.tags_all*",
    "*.description*",
)


def _address_variants(address: str, attribute: str | None) -> list[str]:
    variants = [address]
    if attribute:
        variants.append(f"{address}.{attribute}")
        # also the bare "type.*.attr" shape tfdrift ignore files use
        rtype = address.split(".", 1)[0]
        variants.append(f"{rtype}.*.{attribute}")
        variants.append(f"*.{attribute}")
    return variants


def classify_severity(address: str, actions: list[str], attribute: str | None) -> str:
    """Severity from resource type/attribute and action, tfdrift-style."""
    variants = _address_variants(address, attribute)

    def matches(patterns):
        return any(fnmatch.fnmatch(v, p) for v in variants for p in patterns)

    if matches(CRITICAL_PATTERNS):
        return "critical"
    if "delete" in actions:
        # Out-of-band deletion of a managed resource is always serious.
        return "high"
    if matches(HIGH_PATTERNS):
        return "high"
    if matches(LOW_PATTERNS):
        return "low"
    return "medium"


def is_ignored(address: str, attribute: str | None, ignore_patterns: list[str]) -> bool:
    if not ignore_patterns:
        return False
    variants = _address_variants(address, attribute)
    return any(fnmatch.fnmatch(v, p) for v in variants for p in ignore_patterns)


def _drift_actions(change: dict[str, Any]) -> list[str]:
    actions = [a for a in change.get("actions", []) if a != "no-op"]
    return actions


def _changed_attributes(change: dict[str, Any]) -> list[str]:
    before = change.get("before") or {}
    after = change.get("after") or {}
    if not isinstance(before, dict) or not isinstance(after, dict):
        return []
    keys = set(before) | set(after)
    return sorted(k for k in keys if before.get(k) != after.get(k))


def extract_drift(plan: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize drifted resources from a `terraform show -json` document.

    Prefers the dedicated top-level `resource_drift` (Terraform >= 0.15.4);
    falls back to non-no-op `resource_changes`.
    """
    entries: list[dict[str, Any]] = []
    source = plan.get("resource_drift")
    if not source:
        source = [
            rc for rc in plan.get("resource_changes", [])
            if _drift_actions(rc.get("change", {}))
        ]
    for item in source:
        if not isinstance(item, dict):
            raise ValueError(f"drift entry must be an object, got {type(item).__name__}")
        address = str(item.get("address") or "unknown")
        change = item.get("change", {}) or {}
        actions = _drift_actions(change) or ["update"]
        attributes = _changed_attributes(change)
        entries.append({
            "address": address,
            "type": str(item.get("type") or address.split(".", 1)[0]),
            "actions": actions,
            "changed_attributes": attributes,
        })
    return entries


def evaluate(
    drift_entries: list[dict[str, Any]],
    ignore_patterns: list[str],
) -> dict[str, Any]:
    classified: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    for entry in drift_entries:
        primary_attr = entry["changed_attributes"][0] if entry["changed_attributes"] else None
        if is_ignored(entry["address"], primary_attr, ignore_patterns) or (
            entry["changed_attributes"]
            and all(is_ignored(entry["address"], a, ignore_patterns)
                    for a in entry["changed_attributes"])
        ):
            ignored.append({**entry, "reason": "matched DRIFT_IGNORE (expected drift)"})
            continue
        # Worst severity across the changed attributes.
        severities = [
            classify_severity(entry["address"], entry["actions"], attr)
            for attr in (entry["changed_attributes"] or [None])
        ]
        severity = max(severities, key=lambda s: SEVERITY_ORDER[s])
        classified.append({**entry, "severity": severity})
    return {"classified": classified, "ignored": ignored}


def build_evidence(
    result: dict[str, Any],
    *,
    fail_severity: str,
    remediation_mode: str,
    data_source: str,
    plan_ref: str,
) -> dict[str, Any]:
    classified = result["classified"]
    by_severity: dict[str, int] = {}
    for entry in classified:
        by_severity[entry["severity"]] = by_severity.get(entry["severity"], 0) + 1
    threshold = SEVERITY_ORDER[fail_severity]
    actionable = [e for e in classified if SEVERITY_ORDER[e["severity"]] >= threshold]
    status = Status.FAIL if actionable else Status.PASS
    return {
        "lab_id": LAB_ID,
        "checked_at": utc_now().isoformat(),
        "status": status.value,
        "data_source": data_source,
        "plan_reference": plan_ref,
        "drifted_resource_count": len(classified),
        "drift_by_severity": by_severity,
        "actionable_drift": actionable,
        "actionable_drift_count": len(actionable),
        "all_drift": classified,
        "ignored_drift": result["ignored"],
        "ignored_count": len(result["ignored"]),
        "policy": {
            "fail_severity": fail_severity,
            "remediation_mode": remediation_mode,
            "remediation_note": (
                "Remediation is a gated CI apply with approval (tfdrift safety "
                "model); this lab reports and alerts only."
            ),
        },
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "methodology": {
            "drift_signal": "terraform show -json: resource_drift, else non-no-op resource_changes",
            "severity_model": "tfdrift-style resource/attribute classification (critical/high/medium/low)",
            "ignore_model": ".tfdriftignore-style glob patterns via DRIFT_IGNORE",
            "producer": "CI runs terraform plan -refresh-only and drops the JSON in the plan bucket",
            "persistent_cadence": "daily EventBridge schedule",
        },
    }


def build_provenance(
    context: Any,
    runtime: RuntimeContext,
    event: dict[str, Any],
    plan_ref: str,
) -> dict[str, Any]:
    """Provenance that binds the evidence to the exact change and collector.

    The Terraform commit and workspace come from the CI producer (event or
    env); without them the assurance case is honestly marked 'unknown'.
    """
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
        "plan_reference": plan_ref,
        "evidence_manifest_sha256": None,  # filled after the package is assembled
    }


def build_assurance_case(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """Assessor-facing objective -> claim -> status -> evidence mapping.

    Status is OTHER-THAN-SATISFIED when actionable drift exists (the baseline
    is not being enforced), SATISFIED when the evaluated plan is clean.
    """
    overall = Status(evidence["status"])
    satisfied = overall is Status.PASS
    status_label = "SATISFIED" if satisfied else "OTHER-THAN-SATISFIED"
    drift_summary = {
        "drifted_resource_count": evidence["drifted_resource_count"],
        "actionable_drift_count": evidence["actionable_drift_count"],
        "drift_by_severity": evidence["drift_by_severity"],
    }
    case = []
    for control in SCF_CONTROLS:
        meta = CONTROL_ASSESSMENT[control]
        case.append({
            "scf_control": control,
            "title": meta["title"],
            "claim": meta["claim"],
            "status": status_label,
            "nist_800_171_r3_objectives": meta["nist_800_171_r3"],
            "nist_800_53_r5_objectives": meta["nist_800_53_r5"],
            "odp_references": meta["odp_references"],
            "evidence": {
                "plan_reference": evidence["plan_reference"],
                "drift_summary": drift_summary,
                "artifact": "self (this evidence object)",
            },
        })
    return case


def evidence_manifest_sha256(evidence: dict[str, Any]) -> str:
    """Deterministic integrity hash over the assembled package (excluding the
    manifest field and the post-hoc S3 URI). Binds this specific package so
    tampering is detectable."""
    payload = {
        k: v for k, v in evidence.items()
        if k not in ("evidence_uri",)
    }
    payload = json.loads(json.dumps(payload, default=str))
    if payload.get("provenance", {}).get("evidence_manifest_sha256") is not None:
        payload["provenance"] = dict(payload["provenance"])
        payload["provenance"]["evidence_manifest_sha256"] = None
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_plan(
    event: dict[str, Any],
    s3_client: Any,
) -> tuple[dict[str, Any], str, str]:
    """Return (plan_json, data_source, plan_reference).

    Priority: event-embedded plan, then the plan-artifact S3 object.
    """
    if isinstance(event.get("plan"), dict):
        return event["plan"], "event", "event.plan"
    bucket = os.environ.get("PLAN_BUCKET", "").strip()
    key = (event.get("plan_key") or os.environ.get("PLAN_KEY", "")).strip()
    if not bucket or not key:
        raise ConfigError(
            "no Terraform plan supplied — set PLAN_BUCKET/PLAN_KEY (CI drops "
            "`terraform show -json` there) or pass event.plan"
        )
    if s3_client is None:  # pragma: no cover - AWS only
        import boto3

        s3_client = boto3.client("s3")
    body = s3_client.get_object(Bucket=bucket, Key=key)["Body"].read()
    return json.loads(body), "s3", f"s3://{bucket}/{key}"


def _simulation_plan() -> dict[str, Any]:
    """Deterministic demo plan: a critical SG-ingress drift, a low tag drift,
    and one ignored autoscaling drift."""
    return {
        "format_version": "1.2",
        "resource_drift": [
            {
                "address": "aws_security_group.web.ingress",
                "type": "aws_security_group",
                "change": {
                    "actions": ["update"],
                    "before": {"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]},
                    "after": {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
                },
            },
            {
                "address": "aws_instance.app",
                "type": "aws_instance",
                "change": {
                    "actions": ["update"],
                    "before": {"tags": {"env": "prod"}},
                    "after": {"tags": {"env": "prod", "LastModified": "2026-08-01"}},
                },
            },
            {
                "address": "aws_autoscaling_group.workers",
                "type": "aws_autoscaling_group",
                "change": {
                    "actions": ["update"],
                    "before": {"desired_capacity": 3},
                    "after": {"desired_capacity": 5},
                },
            },
        ],
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
        remediation_mode = os.environ.get("REMEDIATION_MODE", "report").strip().lower()
        if remediation_mode not in {"report", "dry_run"}:
            raise ConfigError("REMEDIATION_MODE must be report|dry_run")
        ignore_patterns = get_csv_env("DRIFT_IGNORE", default=[])

        if simulation_requested(event):
            plan, data_source, plan_ref = _simulation_plan(), "simulation", "simulation"
        else:
            plan, data_source, plan_ref = load_plan(event, s3_client)

        drift_entries = extract_drift(plan)
        result = evaluate(drift_entries, ignore_patterns)
        evidence = build_evidence(
            result,
            fail_severity=fail_severity,
            remediation_mode=remediation_mode,
            data_source=data_source,
            plan_ref=plan_ref,
        )
        status = Status(evidence["status"])

        # Assessor-ready assurance case: bind evidence to the change and the
        # collector, map to NIST assessment objectives + ODPs, and seal the
        # package with an integrity manifest hash.
        evidence["provenance"] = build_provenance(context, runtime, event, plan_ref)
        evidence["assurance_case"] = build_assurance_case(evidence)
        evidence["provenance"]["evidence_manifest_sha256"] = evidence_manifest_sha256(evidence)

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is Status.FAIL:
            emitter = AsffEmitter(LAB_ID, runtime, client=securityhub_client)
            emitter.emit([emitter.build_finding(
                finding_id=f"tf-drift/{run_id}",
                title="Terraform-managed infrastructure has drifted out of band",
                description=(
                    f"{evidence['actionable_drift_count']} drifted resource(s) at or above "
                    f"{fail_severity} severity across {evidence['drifted_resource_count']} "
                    f"total drift(s). Baseline enforcement (KSI-CNA-EIS) violated."
                ),
                severity="HIGH",
                resource_type="Other",
                resource_id=f"account/{runtime.account_id}/terraform-drift",
                status=status,
            )])
            publish_alert(
                LAB_ID,
                status,
                f"{evidence['actionable_drift_count']} actionable drift(s) "
                f"(>= {fail_severity}); {evidence['drifted_resource_count']} total, "
                f"{evidence['ignored_count']} ignored",
                sns_client=sns_client,
            )
        logger.info(
            "terraform drift sweep complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "drifted": evidence["drifted_resource_count"],
                "actionable": evidence["actionable_drift_count"],
                "data_source": data_source,
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
