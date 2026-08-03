"""Incident response automation readiness validation.

Wire EventBridge (daily schedule) → this function → Security Hub / evidence
store. The lab attests that the IR program's automation is actually deployable
*right now* — not that a playbook document exists in a wiki:

  1. Runbook presence (KSI-INR-IRP/PRC): every SSM document named in
     REQUIRED_RUNBOOKS must exist and be in ``Status == "Active"``. A missing
     or non-Active runbook means the containment/forensics automation cannot
     be invoked during an incident.
  2. Escalation readiness (KSI-MLA-OSM): the SNS escalation topic
     (SNS_TOPIC_ARN) must have at least one *confirmed* subscriber —
     an alert published into a topic nobody receives is not escalation.

Event sources:
  * Scheduled sweep — runbooks checked via SSM DescribeDocument, topic via
    SNS GetTopicAttributes
  * ``{"mode": "simulation"}`` — fixed demo check results, stamped as simulated

Verdict semantics (fail closed):
  * CONFIG_ERROR — REQUIRED_RUNBOOKS unset/empty (an IR program with no
    required runbooks is a configuration gap, never a PASS) or SNS_TOPIC_ARN
    unset.
  * FAIL — any runbook missing/inactive, or zero confirmed escalation
    subscribers. An ASFF finding is imported on FAIL.
  * PASS — every required runbook Active and the escalation path confirmed.

Env contract: EVIDENCE_BUCKET, SNS_TOPIC_ARN, REQUIRED_RUNBOOKS (CSV of SSM
document names, e.g. "ir-isolate-instance,ir-snapshot-forensics"), LOG_LEVEL.
"""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

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
    require_env,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "09-incident-response-automation"
SCF_CONTROLS = ["IRO-01", "IRO-02", "IRO-04", "IRO-10", "MON-02"]
FEDRAMP_KSI = ["KSI-INR-IRP", "KSI-INR-PRC", "KSI-MLA-OSM"]

logger = get_logger(LAB_ID)


# --------------------------------------------------------------------------
# Checks — real API reads; this is what PASS hangs on
# --------------------------------------------------------------------------

def check_runbook(name: str, ssm_client: Any) -> dict[str, Any]:
    """One required runbook: the SSM document must exist and be Active.
    InvalidDocument is the documented not-found error and is a violation, not
    an ERROR; any other ClientError propagates (SDK failure → ERROR)."""
    try:
        document = ssm_client.describe_document(Name=name).get("Document", {})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "InvalidDocument":
            return {
                "name": name,
                "present": False,
                "document_status": None,
                "document_version": None,
                "finding": f"runbook missing — SSM document {name!r} not found",
            }
        raise
    document_status = document.get("Status", "")
    finding = None
    if document_status != "Active":
        finding = (
            f"runbook {name!r} document status is {document_status or 'unknown'!r} "
            "— must be Active to be invocable during an incident"
        )
    return {
        "name": name,
        "present": True,
        "document_status": document_status,
        "document_version": document.get("DocumentVersion"),
        "finding": finding,
    }


def check_escalation_topic(topic_arn: str, sns_client: Any) -> dict[str, Any]:
    """Escalation topic must have at least one confirmed subscriber."""
    attributes = sns_client.get_topic_attributes(TopicArn=topic_arn).get("Attributes", {})
    confirmed = int(attributes.get("SubscriptionsConfirmed", "0"))
    pending = int(attributes.get("SubscriptionsPending", "0"))
    finding = None
    if confirmed <= 0:
        finding = (
            "no confirmed escalation subscribers on the escalation topic — "
            "alerts would be published into the void"
        )
    return {
        "topic_arn": topic_arn,
        "subscriptions_confirmed": confirmed,
        "subscriptions_pending": pending,
        "finding": finding,
    }


def build_evidence(
    runbook_results: list[dict[str, Any]],
    topic_check: dict[str, Any],
    data_source: str,
) -> dict[str, Any]:
    violations: list[dict[str, Any]] = [
        {"type": "runbook", "name": r["name"], "detail": r["finding"]}
        for r in runbook_results
        if r["finding"]
    ]
    if topic_check["finding"]:
        violations.append({
            "type": "escalation_topic",
            "topic_arn": topic_check["topic_arn"],
            "detail": topic_check["finding"],
        })
    status = Status.FAIL if violations else Status.PASS
    return {
        "lab_id": LAB_ID,
        "checked_at": utc_now().isoformat(),
        "status": status.value,
        "data_source": data_source,
        "required_runbook_count": len(runbook_results),
        "runbooks": runbook_results,
        "runbooks_missing": [r["name"] for r in runbook_results if not r["present"]],
        "runbooks_inactive": [
            r["name"]
            for r in runbook_results
            if r["present"] and r["document_status"] != "Active"
        ],
        "escalation_topic": topic_check,
        "violations": violations,
        "violation_count": len(violations),
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "methodology": {
            "runbooks": "SSM DescribeDocument per required runbook; Status must be Active",
            "escalation": "SNS GetTopicAttributes; SubscriptionsConfirmed must be > 0",
            "persistent_cadence": "daily EventBridge schedule",
        },
    }


def _simulation_checks() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Small deterministic demo: one Active runbook, one missing runbook →
    deterministic FAIL, escalation path healthy."""
    runbooks = [
        {
            "name": "ir-isolate-instance",
            "present": True,
            "document_status": "Active",
            "document_version": "3",
            "finding": None,
        },
        {
            "name": "ir-snapshot-forensics",
            "present": False,
            "document_status": None,
            "document_version": None,
            "finding": "runbook missing — SSM document 'ir-snapshot-forensics' not found",
        },
    ]
    topic = {
        "topic_arn": "simulated://escalation-topic",
        "subscriptions_confirmed": 2,
        "subscriptions_pending": 0,
        "finding": None,
    }
    return runbooks, topic


def handler(
    event: dict[str, Any],
    context: Any,
    ssm_client: Any = None,
    sns_client: Any = None,
    s3_client: Any = None,
    securityhub_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        runtime = RuntimeContext.from_lambda(context)  # fail closed if we can't tell where we run

        if simulation_requested(event):
            runbook_results, topic_check = _simulation_checks()
            data_source = "simulation"
        else:
            # No default: an unset runbook register is a configuration gap.
            required = get_csv_env("REQUIRED_RUNBOOKS")
            if not required:
                raise ConfigError(
                    "REQUIRED_RUNBOOKS resolved to an empty list — an IR program "
                    "with zero required runbooks is a configuration gap, not a PASS"
                )
            topic_arn = require_env("SNS_TOPIC_ARN")
            if ssm_client is None:  # pragma: no cover - AWS only
                import boto3

                ssm_client = boto3.client("ssm")
            if sns_client is None:  # pragma: no cover - AWS only
                import boto3

                # Same injectable client serves the subscription check and the
                # non-PASS alert below — one escalation path, checked then used.
                sns_client = boto3.client("sns")
            runbook_results = [check_runbook(name, ssm_client) for name in required]
            topic_check = check_escalation_topic(topic_arn, sns_client)
            data_source = "aws-api"

        evidence = build_evidence(runbook_results, topic_check, data_source)
        status = Status(evidence["status"])

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is Status.FAIL:
            emitter = AsffEmitter(LAB_ID, runtime, client=securityhub_client)
            emitter.emit([emitter.build_finding(
                finding_id=f"ir-readiness/{run_id}",
                title="Incident response automation not ready",
                description=(
                    f"{len(evidence['runbooks_missing'])} runbook(s) missing, "
                    f"{len(evidence['runbooks_inactive'])} inactive, "
                    f"{topic_check['subscriptions_confirmed']} confirmed escalation "
                    "subscriber(s). Fails KSI-INR-IRP/PRC readiness."
                ),
                severity="HIGH",
                resource_type="Other",
                resource_id=f"account/{runtime.account_id}/ir-automation",
                status=status,
            )])
        if status is not Status.PASS:
            publish_alert(
                LAB_ID,
                status,
                f"{evidence['violation_count']} IR readiness violation(s) across "
                f"{evidence['required_runbook_count']} required runbook(s); "
                f"confirmed escalation subscribers: "
                f"{topic_check['subscriptions_confirmed']}",
                sns_client=sns_client,
            )
        logger.info(
            "ir readiness check complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "runbooks": evidence["required_runbook_count"],
                "missing": len(evidence["runbooks_missing"]),
                "violations": evidence["violation_count"],
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
