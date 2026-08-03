"""Amazon Inspector → Security Hub → VDR orchestrator.

Implements a FedRAMP 20x KSI-AFR-VDR style severity → SLA matrix (N1–N5)
and records remediation evidence timestamps.

Event sources:
  * EventBridge Security Hub finding events (``event.detail.findings``)
  * Scheduled sweep — findings are pulled from Security Hub (paginated)
  * ``{"mode": "simulation"}`` — a fixed demo finding, stamped as simulated
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from lab_common import (
    ConfigError,
    EvidenceWriter,
    RuntimeContext,
    Status,
    get_logger,
    new_run_id,
    parse_iso8601,
    publish_alert,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "02-inspector-vdr"
SCF_CONTROLS = ["VPM-01", "VPM-02", "MON-01", "THR-01"]
FEDRAMP_KSI = ["KSI-AFR-VDR", "KSI-AFR-PVL", "KSI-MLA-EVC"]

logger = get_logger(LAB_ID)

# FedRAMP-style severity bands → remediation windows (tune to your ATO package)
SLA_DAYS = {
    "N1": 1,    # critical / actively exploited
    "N2": 7,    # high
    "N3": 30,   # medium
    "N4": 90,   # low
    "N5": 180,  # informational / accepted risk review
}

SEVERITY_TO_N = {
    "CRITICAL": "N1",
    "HIGH": "N2",
    "MEDIUM": "N3",
    "LOW": "N4",
    "INFORMATIONAL": "N5",
}


def classify(severity_label: str) -> str:
    return SEVERITY_TO_N.get(severity_label.upper(), "N3")


def sla_deadline(first_observed: datetime, n_level: str) -> datetime:
    return first_observed + timedelta(days=SLA_DAYS[n_level])


def normalize_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize Security Hub / Inspector finding fields.

    Timestamps go through ``parse_iso8601`` so naive values are treated as
    UTC instead of raising TypeError when compared with aware datetimes.
    """
    severity = (
        raw.get("Severity", {}).get("Label")
        or raw.get("severity")
        or "MEDIUM"
    )
    observed = raw.get("FirstObservedAt") or raw.get("CreatedAt")
    if isinstance(observed, str):
        first = parse_iso8601(observed)
    else:
        first = utc_now()
    n_level = classify(str(severity))
    deadline = sla_deadline(first, n_level)
    now = utc_now()
    return {
        "finding_id": raw.get("Id") or raw.get("findingArn") or "unknown",
        "title": raw.get("Title") or raw.get("title") or "untitled",
        "severity": str(severity).upper(),
        "n_level": n_level,
        "sla_days": SLA_DAYS[n_level],
        "first_observed_at": first.isoformat(),
        "sla_deadline_at": deadline.isoformat(),
        "breached": now > deadline,
        "resource": (raw.get("Resources") or [{}])[0].get("Id", "unknown"),
    }


def fetch_open_findings(securityhub_client: Any) -> list[dict[str, Any]]:
    """Pull all ACTIVE, unresolved Inspector findings from Security Hub.

    Fully paginated — a truncated pull would understate the population under
    audit, which is exactly the failure mode this lab exists to catch.
    """
    paginator = securityhub_client.get_paginator("get_findings")
    filters = {
        "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [
            {"Value": "NEW", "Comparison": "EQUALS"},
            {"Value": "NOTIFIED", "Comparison": "EQUALS"},
        ],
    }
    findings: list[dict[str, Any]] = []
    for page in paginator.paginate(Filters=filters):
        findings.extend(page.get("Findings", []))
    return findings


def build_evidence(findings: list[dict[str, Any]], data_source: str) -> dict[str, Any]:
    breached = [f for f in findings if f["breached"]]
    open_by_n: dict[str, int] = {}
    for f in findings:
        open_by_n[f["n_level"]] = open_by_n.get(f["n_level"], 0) + 1
    status = Status.FAIL if breached else Status.PASS
    return {
        "lab_id": LAB_ID,
        "checked_at": utc_now().isoformat(),
        "status": status.value,
        "data_source": data_source,
        "open_findings": len(findings),
        "sla_breaches": len(breached),
        "open_by_n_level": open_by_n,
        "sla_matrix_days": SLA_DAYS,
        # Complete list — no silent truncation; the counts above are
        # authoritative and this array matches them.
        "breached_findings": breached,
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "methodology": {
            "scanner": "Amazon Inspector",
            "aggregator": "AWS Security Hub",
            "rating_scheme": "N1-N5",
            "persistent_cadence": "daily EventBridge schedule",
        },
    }


def _simulation_findings() -> list[dict[str, Any]]:
    return [
        {
            "Id": "sim-cve-critical",
            "Title": "Simulated critical package CVE",
            "Severity": {"Label": "CRITICAL"},
            "FirstObservedAt": (utc_now() - timedelta(days=3)).isoformat(),
            "Resources": [{"Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-simulated"}],
        }
    ]


def _extract_event_findings(event: dict[str, Any]) -> list[dict[str, Any]]:
    findings = event.get("findings") or event.get("detail", {}).get("findings") or []
    if not findings and isinstance(event.get("detail"), dict) and "findings" not in event["detail"]:
        detail = event["detail"]
        if detail:
            findings = [detail]
    return findings


def handler(
    event: dict[str, Any],
    context: Any,
    securityhub_client: Any = None,
    s3_client: Any = None,
    sns_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        RuntimeContext.from_lambda(context)  # fail closed if we can't tell where we run

        raw_findings = _extract_event_findings(event)
        if simulation_requested(event):
            raw_findings = raw_findings or _simulation_findings()
            data_source = "simulation"
        elif raw_findings:
            data_source = "event"
        else:
            if securityhub_client is None:  # pragma: no cover - AWS only
                import boto3

                securityhub_client = boto3.client("securityhub")
            raw_findings = fetch_open_findings(securityhub_client)
            data_source = "securityhub"

        normalized = [normalize_finding(f) for f in raw_findings]
        evidence = build_evidence(normalized, data_source)
        status = Status(evidence["status"])

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is not Status.PASS:
            publish_alert(
                LAB_ID,
                status,
                f"{evidence['sla_breaches']} SLA breach(es) across "
                f"{evidence['open_findings']} open findings",
                sns_client=sns_client,
            )
        logger.info(
            "vdr sweep complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "open": evidence["open_findings"],
                "breaches": evidence["sla_breaches"],
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
