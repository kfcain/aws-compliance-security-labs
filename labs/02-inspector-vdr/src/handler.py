"""
Amazon Inspector → Security Hub → VDR orchestrator.

Implements a FedRAMP 20x KSI-AFR-VDR style severity → SLA matrix (N1–N5)
and records remediation evidence timestamps.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any


LAB_ID = "02-inspector-vdr"
SCF_CONTROLS = ["VPM-01", "VPM-02", "MON-01", "THR-01"]
FEDRAMP_KSI = ["KSI-AFR-VDR", "KSI-AFR-PVL", "KSI-MLA-EVC"]

# FedRAMP-style severity bands → remediation windows (tune to your ATO package)
SLA_DAYS = {
    "N1": 1,   # critical / actively exploited
    "N2": 7,   # high
    "N3": 30,  # medium
    "N4": 90,  # low
    "N5": 180, # informational / accepted risk review
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
    """Normalize Security Hub / Inspector finding fields."""
    severity = (
        raw.get("Severity", {}).get("Label")
        or raw.get("severity")
        or "MEDIUM"
    )
    observed = raw.get("FirstObservedAt") or raw.get("CreatedAt")
    if isinstance(observed, str):
        first = datetime.fromisoformat(observed.replace("Z", "+00:00"))
    else:
        first = datetime.now(timezone.utc)
    n_level = classify(str(severity))
    deadline = sla_deadline(first, n_level)
    now = datetime.now(timezone.utc)
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


def build_evidence(findings: list[dict[str, Any]]) -> dict[str, Any]:
    breached = [f for f in findings if f["breached"]]
    open_by_n: dict[str, int] = {}
    for f in findings:
        open_by_n[f["n_level"]] = open_by_n.get(f["n_level"], 0) + 1
    status = "FAIL" if breached else "PASS"
    return {
        "lab_id": LAB_ID,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "open_findings": len(findings),
        "sla_breaches": len(breached),
        "open_by_n_level": open_by_n,
        "sla_matrix_days": SLA_DAYS,
        "breached_findings": breached[:50],
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "methodology": {
            "scanner": "Amazon Inspector",
            "aggregator": "AWS Security Hub",
            "rating_scheme": "N1-N5",
            "persistent_cadence": "daily EventBridge schedule",
        },
    }


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Event sources:
      - EventBridge Security Hub finding events
      - Scheduled sweep with findings embedded under event['findings']
    """
    raw_findings = event.get("findings") or event.get("detail", {}).get("findings") or []
    if not raw_findings and event.get("detail"):
        raw_findings = [event["detail"]]

    # Demo path when invoked with empty schedule
    if not raw_findings:
        raw_findings = [
            {
                "Id": "demo-cve-2024",
                "Title": "Demo critical package CVE",
                "Severity": {"Label": "CRITICAL"},
                "FirstObservedAt": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
                "Resources": [{"Id": "arn:aws:ec2:us-east-1:123:instance/i-demo"}],
            }
        ]

    normalized = [normalize_finding(f) for f in raw_findings]
    evidence = build_evidence(normalized)
    # Production: write evidence to S3, open ITSM ticket for breaches, optional SSM patch
    print(json.dumps({"status": evidence["status"], "breaches": evidence["sla_breaches"]}))
    return {"statusCode": 200, "body": json.dumps(evidence)}
