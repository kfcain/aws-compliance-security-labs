"""Continuous Config Drift & Control Status — Lambda entrypoint.

Wire EventBridge → this function → Security Hub / evidence store.

Uses AWS Config as the drift sensor:

  1. The configuration recorder must exist and be recording — a stopped
     recorder means the control is not operating at all (CONFIG_ERROR).
  2. Every Config rule is inventoried (paginated) and its account-level
     ComplianceType pulled (paginated). Any NON_COMPLIANT rule is drift → FAIL.
  3. INSUFFICIENT_DATA is reported explicitly — it never passes silently.
     PASS requires zero NON_COMPLIANT rules and at least one rule that has
     actually evaluated COMPLIANT. Zero rules configured is CONFIG_ERROR.

``{"mode": "simulation"}`` evaluates a fixed demo rule set, stamped
``data_source: simulation``.
"""
from __future__ import annotations

from typing import Any

from lab_common import (
    AsffEmitter,
    ConfigError,
    EvidenceWriter,
    RuntimeContext,
    Status,
    get_logger,
    new_run_id,
    publish_alert,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "04-config-drift-compliance"
SCF_CONTROLS = ["CFG-01", "CFG-02", "CPL-01", "CPL-02", "MON-01"]
FEDRAMP_KSI = ["KSI-CNA-EIS", "KSI-MLA-EVC", "KSI-AFR-PVL"]

logger = get_logger(LAB_ID)


def check_recorders(config_client: Any) -> list[dict[str, Any]]:
    """Recorder posture. No recorder, or none recording → ConfigError:
    with the recorder off there is no drift signal, so the control is not
    operating and must never report PASS."""
    statuses = config_client.describe_configuration_recorder_status().get(
        "ConfigurationRecordersStatus", []
    )
    if not statuses:
        raise ConfigError(
            "no AWS Config configuration recorder exists — drift detection is not operating"
        )
    recorders = [
        {
            "name": s.get("name", "default"),
            "recording": bool(s.get("recording")),
            "last_status": s.get("lastStatus", "UNKNOWN"),
        }
        for s in statuses
    ]
    if not any(r["recording"] for r in recorders):
        raise ConfigError(
            "AWS Config recorder(s) exist but none are recording — "
            "drift detection is not operating"
        )
    return recorders


def fetch_config_rules(config_client: Any) -> list[dict[str, Any]]:
    """Full rule inventory — paginated so a large rule pack is never truncated."""
    rules: list[dict[str, Any]] = []
    paginator = config_client.get_paginator("describe_config_rules")
    for page in paginator.paginate():
        for rule in page.get("ConfigRules", []):
            rules.append(
                {
                    "name": rule.get("ConfigRuleName", "unknown"),
                    "source": (rule.get("Source") or {}).get("SourceIdentifier", "unknown"),
                    "state": rule.get("ConfigRuleState", "UNKNOWN"),
                }
            )
    return rules


def fetch_rule_compliance(config_client: Any) -> list[dict[str, Any]]:
    """Per-rule account-level ComplianceType — paginated."""
    results: list[dict[str, Any]] = []
    paginator = config_client.get_paginator("describe_compliance_by_config_rule")
    for page in paginator.paginate():
        for entry in page.get("ComplianceByConfigRules", []):
            results.append(
                {
                    "rule_name": entry.get("ConfigRuleName", "unknown"),
                    "compliance_type": (entry.get("Compliance") or {}).get(
                        "ComplianceType", "INSUFFICIENT_DATA"
                    ),
                }
            )
    return results


def build_evidence(
    recorders: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    compliance: list[dict[str, Any]],
    data_source: str,
) -> dict[str, Any]:
    by_type: dict[str, list[str]] = {
        "COMPLIANT": [],
        "NON_COMPLIANT": [],
        "INSUFFICIENT_DATA": [],
        "NOT_APPLICABLE": [],
    }
    for entry in compliance:
        by_type.setdefault(entry["compliance_type"], []).append(entry["rule_name"])
    non_compliant = by_type["NON_COMPLIANT"]
    compliant = by_type["COMPLIANT"]
    insufficient = by_type["INSUFFICIENT_DATA"]

    if non_compliant:
        status = Status.FAIL
        reason = (
            f"{len(non_compliant)} Config rule(s) NON_COMPLIANT: "
            f"{', '.join(sorted(non_compliant))}"
        )
    elif compliant:
        status = Status.PASS
        reason = f"{len(compliant)} rule(s) COMPLIANT, 0 NON_COMPLIANT"
        if insufficient:
            reason += f"; {len(insufficient)} INSUFFICIENT_DATA rule(s) reported for follow-up"
    else:
        # Rules exist but none has produced a COMPLIANT evaluation — the
        # control cannot be shown to operate, so fail closed (never PASS
        # on INSUFFICIENT_DATA alone).
        status = Status.FAIL
        reason = (
            "no Config rule has evaluated COMPLIANT — only INSUFFICIENT_DATA/"
            "NOT_APPLICABLE results; drift monitoring cannot be shown to operate"
        )

    return {
        "lab_id": LAB_ID,
        "checked_at": utc_now().isoformat(),
        "status": status.value,
        "data_source": data_source,
        "recorders": recorders,
        "rule_count": len(rules),
        "rules": rules,
        "rule_compliance": compliance,
        "counts": {kind.lower(): len(names) for kind, names in by_type.items()},
        "non_compliant_rules": sorted(non_compliant),
        "insufficient_data_rules": sorted(insufficient),
        "verdict_reason": reason,
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "methodology": {
            "sensor": "AWS Config recorder + managed/custom rules",
            "aggregation": "describe_compliance_by_config_rule (account level, paginated)",
            "persistent_cadence": "EventBridge schedule (<= 3 days for FedRAMP 20x)",
        },
    }


def _simulation_dataset() -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]
]:
    """Small deterministic demo: one drifted rule, one healthy, one unevaluated."""
    recorders = [{"name": "simulated-recorder", "recording": True, "last_status": "SUCCESS"}]
    rules = [
        {
            "name": "s3-bucket-public-read-prohibited",
            "source": "S3_BUCKET_PUBLIC_READ_PROHIBITED",
            "state": "ACTIVE",
        },
        {"name": "restricted-ssh", "source": "INCOMING_SSH_DISABLED", "state": "ACTIVE"},
        {
            "name": "root-account-mfa-enabled",
            "source": "ROOT_ACCOUNT_MFA_ENABLED",
            "state": "ACTIVE",
        },
    ]
    compliance = [
        {"rule_name": "s3-bucket-public-read-prohibited", "compliance_type": "NON_COMPLIANT"},
        {"rule_name": "restricted-ssh", "compliance_type": "COMPLIANT"},
        {"rule_name": "root-account-mfa-enabled", "compliance_type": "INSUFFICIENT_DATA"},
    ]
    return recorders, rules, compliance


def handler(
    event: dict[str, Any],
    context: Any,
    config_client: Any = None,
    securityhub_client: Any = None,
    s3_client: Any = None,
    sns_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        runtime = RuntimeContext.from_lambda(context)

        if simulation_requested(event):
            recorders, rules, compliance = _simulation_dataset()
            data_source = "simulation"
        else:
            if config_client is None:  # pragma: no cover - AWS only
                import boto3

                config_client = boto3.client("config")
            recorders = check_recorders(config_client)
            rules = fetch_config_rules(config_client)
            if not rules:
                raise ConfigError(
                    "no Config rules to evaluate — deploy the SCF-mapped rule pack "
                    "before relying on this control"
                )
            compliance = fetch_rule_compliance(config_client)
            data_source = "aws-api"

        evidence = build_evidence(recorders, rules, compliance, data_source)
        status = Status(evidence["status"])

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )

        if status is Status.FAIL:
            emitter = AsffEmitter(LAB_ID, runtime, client=securityhub_client)
            emitter.emit([emitter.build_finding(
                finding_id="config-drift",
                title="Configuration drift: Config rules non-compliant or not evaluating",
                description=evidence["verdict_reason"],
                severity="HIGH",
                resource_type="Other",
                resource_id=f"account/{runtime.account_id}",
                status=status,
                extra_product_fields={
                    "non_compliant_count": str(evidence["counts"]["non_compliant"]),
                    "rule_count": str(evidence["rule_count"]),
                },
            )])
        if status is not Status.PASS:
            publish_alert(LAB_ID, status, evidence["verdict_reason"], sns_client=sns_client)

        logger.info(
            "config drift sweep complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "rules": evidence["rule_count"],
                "non_compliant": evidence["counts"]["non_compliant"],
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
