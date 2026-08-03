"""GuardDuty Threat Detection & Automated Response.

Validates that threat detection is actually operating and that no high-severity
findings are sitting unhandled:

  1. At least one GuardDuty detector exists (none → CONFIG_ERROR — the control
     is not deployed) and every detector is ENABLED (disabled → FAIL).
  2. Active findings at or above SEVERITY_THRESHOLD (default 7) updated within
     LOOKBACK_DAYS (default 7) → FAIL with per-finding detail.

Env contract: EVIDENCE_BUCKET, SNS_TOPIC_ARN, SEVERITY_THRESHOLD,
LOOKBACK_DAYS, LOG_LEVEL.
"""
from __future__ import annotations

from datetime import timedelta
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

LAB_ID = "05-guardduty-automated-response"
SCF_CONTROLS = ["THR-01", "THR-03", "MON-01", "MON-02", "IRO-02"]
FEDRAMP_KSI = ["KSI-MLA-OSM", "KSI-INR-PRC", "KSI-CNA-MAT"]

logger = get_logger(LAB_ID)

_GET_FINDINGS_CHUNK = 50  # GetFindings hard limit


def list_detector_ids(guardduty_client: Any) -> list[str]:
    detector_ids: list[str] = []
    for page in guardduty_client.get_paginator("list_detectors").paginate():
        detector_ids.extend(page.get("DetectorIds", []))
    return detector_ids


def detector_posture(detector_id: str, guardduty_client: Any) -> dict[str, Any]:
    detector = guardduty_client.get_detector(DetectorId=detector_id)
    enabled = detector.get("Status") == "ENABLED"
    return {
        "detector_id": detector_id,
        "enabled": enabled,
        "finding_publishing_frequency": detector.get("FindingPublishingFrequency"),
        "finding": None if enabled else (
            f"detector {detector_id} is {detector.get('Status', 'UNKNOWN')} — "
            "threat detection is disabled"
        ),
    }


def fetch_high_severity_findings(
    detector_id: str,
    guardduty_client: Any,
    severity_threshold: int,
    lookback_days: int,
) -> list[dict[str, Any]]:
    """All ACTIVE findings >= threshold updated in the lookback window.

    Fully paginated; details resolved via GetFindings in 50-id chunks.
    """
    updated_after = int((utc_now() - timedelta(days=lookback_days)).timestamp() * 1000)
    criteria = {
        "Criterion": {
            "severity": {"GreaterThanOrEqual": severity_threshold},
            "service.archived": {"Equals": ["false"]},
            "updatedAt": {"GreaterThanOrEqual": updated_after},
        }
    }
    finding_ids: list[str] = []
    paginator = guardduty_client.get_paginator("list_findings")
    for page in paginator.paginate(DetectorId=detector_id, FindingCriteria=criteria):
        finding_ids.extend(page.get("FindingIds", []))

    findings: list[dict[str, Any]] = []
    for start in range(0, len(finding_ids), _GET_FINDINGS_CHUNK):
        chunk = finding_ids[start:start + _GET_FINDINGS_CHUNK]
        detail = guardduty_client.get_findings(DetectorId=detector_id, FindingIds=chunk)
        for f in detail.get("Findings", []):
            resource = f.get("Resource", {})
            findings.append({
                "finding_id": f.get("Id", "unknown"),
                "type": f.get("Type", "unknown"),
                "severity": f.get("Severity"),
                "title": f.get("Title", ""),
                "updated_at": f.get("UpdatedAt", ""),
                "resource_type": resource.get("ResourceType", "unknown"),
            })
    return findings


def severity_band(severity: float | int | None) -> str:
    if severity is None:
        return "unknown"
    if severity >= 8.5:
        return "critical"
    if severity >= 7:
        return "high"
    if severity >= 4:
        return "medium"
    return "low"


def build_evidence(
    detectors: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    *,
    severity_threshold: int,
    lookback_days: int,
    data_source: str,
) -> dict[str, Any]:
    detector_violations = [d["finding"] for d in detectors if d["finding"]]
    by_band: dict[str, int] = {}
    for f in findings:
        band = severity_band(f.get("severity"))
        by_band[band] = by_band.get(band, 0) + 1
    status = Status.FAIL if detector_violations or findings else Status.PASS
    return {
        "lab_id": LAB_ID,
        "checked_at": utc_now().isoformat(),
        "status": status.value,
        "data_source": data_source,
        "detectors": detectors,
        "detector_violations": detector_violations,
        "active_high_severity_findings": findings,
        "finding_count": len(findings),
        "findings_by_band": by_band,
        "policy": {
            "severity_threshold": severity_threshold,
            "lookback_days": lookback_days,
        },
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "methodology": {
            "detection": "GuardDuty detector posture (ListDetectors/GetDetector)",
            "findings": (
                "ListFindings severity>=threshold, unarchived, updated within "
                "lookback; details via GetFindings (50-id chunks)"
            ),
            "persistent_cadence": "daily EventBridge schedule",
        },
    }


def _simulation_dataset() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deterministic demo: one enabled detector, one critical finding → FAIL."""
    detectors = [{
        "detector_id": "sim-detector",
        "enabled": True,
        "finding_publishing_frequency": "FIFTEEN_MINUTES",
        "finding": None,
    }]
    findings = [{
        "finding_id": "sim-finding-1",
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "severity": 8.0,
        "title": "Simulated SSH brute force against i-simulated",
        "updated_at": utc_now().isoformat(),
        "resource_type": "Instance",
    }]
    return detectors, findings


def handler(
    event: dict[str, Any],
    context: Any,
    guardduty_client: Any = None,
    s3_client: Any = None,
    sns_client: Any = None,
    securityhub_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        runtime = RuntimeContext.from_lambda(context)
        severity_threshold = get_int_env("SEVERITY_THRESHOLD", default=7)
        lookback_days = get_int_env("LOOKBACK_DAYS", default=7)

        if simulation_requested(event):
            detectors, findings = _simulation_dataset()
            data_source = "simulation"
        else:
            if guardduty_client is None:  # pragma: no cover - AWS only
                import boto3

                guardduty_client = boto3.client("guardduty")
            detector_ids = list_detector_ids(guardduty_client)
            if not detector_ids:
                raise ConfigError(
                    "no GuardDuty detector in this account/region — enable GuardDuty "
                    "before this control can be evaluated"
                )
            detectors = [detector_posture(d, guardduty_client) for d in detector_ids]
            findings = []
            for d in detectors:
                if d["enabled"]:
                    findings.extend(fetch_high_severity_findings(
                        d["detector_id"], guardduty_client,
                        severity_threshold, lookback_days,
                    ))
            data_source = "guardduty-api"

        evidence = build_evidence(
            detectors, findings,
            severity_threshold=severity_threshold,
            lookback_days=lookback_days,
            data_source=data_source,
        )
        status = Status(evidence["status"])

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is Status.FAIL:
            emitter = AsffEmitter(LAB_ID, runtime, client=securityhub_client)
            emitter.emit([emitter.build_finding(
                finding_id=f"threat-response/{run_id}",
                title="Unhandled high-severity GuardDuty findings or disabled detection",
                description=(
                    f"{len(evidence['detector_violations'])} detector violation(s); "
                    f"{evidence['finding_count']} active finding(s) at severity >= "
                    f"{severity_threshold} within {lookback_days} day(s)."
                ),
                severity="HIGH",
                resource_type="AwsGuardDutyDetector",
                resource_id=f"account/{runtime.account_id}/guardduty",
                status=status,
            )])
        if status is not Status.PASS:
            publish_alert(
                LAB_ID,
                status,
                f"{evidence['finding_count']} high-severity finding(s); "
                f"{len(evidence['detector_violations'])} detector violation(s)",
                sns_client=sns_client,
            )
        logger.info(
            "guardduty sweep complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "detectors": len(detectors),
                "findings": evidence["finding_count"],
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
