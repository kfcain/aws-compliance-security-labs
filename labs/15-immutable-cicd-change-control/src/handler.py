"""
Immutable CI/CD change control & deployment validation.

FedRAMP CR26:
  KSI-CMT-RMV  redeploy version-controlled resources vs direct modification
  KSI-CMT-VTD  automated validation throughout deployment
  KSI-CMT-LMC  log/monitor modifications to the CSO
  KSI-CMT-RVP  review change procedures
  KSI-AFR-SCN  classify significant changes (routine/adaptive/transformative)

Detects forbidden in-place change paths and evaluates pipeline gate evidence.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


LAB_ID = "15-immutable-cicd-change-control"
SCF_CONTROLS = ["CHG-01", "CHG-02", "CHG-03", "CHG-04", "CFG-01", "TDA-06"]
FEDRAMP_KSI = ["KSI-CMT-RMV", "KSI-CMT-VTD", "KSI-CMT-LMC", "KSI-CMT-RVP", "KSI-AFR-SCN"]

# CloudTrail eventName patterns that imply direct modification (lab denylist)
FORBIDDEN_EVENT_NAMES = {
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "AuthorizeSecurityGroupIngress",
    "RevokeSecurityGroupIngress",
    "ModifyDBInstance",
    "PutUserPolicy",
    "AttachUserPolicy",
    "CreateAccessKey",
    "PutRolePolicy",
    "StopLogging",
    "DeleteTrail",
    "UpdateFunctionCode20150331v2",  # prefer pipeline-deployed versions
}

PIPELINE_ACTORS = {
    a.strip()
    for a in os.environ.get(
        "PIPELINE_ACTORS",
        "arn:aws:iam::111111111111:role/CodePipelineServiceRole,codepipeline.amazonaws.com",
    ).split(",")
    if a.strip()
}


@dataclass
class ChangeEvent:
    event_name: str
    event_time: str
    principal: str
    source_ip: str | None
    user_agent: str | None
    resources: list[str] = field(default_factory=list)
    via_pipeline: bool = False


@dataclass
class PipelineRun:
    pipeline_name: str
    commit_sha: str
    gates: dict[str, bool]  # saast|iac_scan|unit|integration|policy_as_code
    deployed: bool
    post_deploy_validation: bool
    change_class: str  # routine | adaptive | transformative


def classify_scn(change_class: str) -> dict[str, Any]:
    """Significant Change Notification timing hints (FedRAMP SCN practice)."""
    windows = {
        "routine": {"notify_before_days": 0, "notes": "Standard pipeline change; log only"},
        "adaptive": {"notify_before_days": 30, "notes": "Notify FedRAMP/agency per adaptive SCN"},
        "transformative": {
            "notify_before_days": 60,
            "notes": "Transformative — early engagement + possible re-assessment",
        },
    }
    return {"change_class": change_class, **windows.get(change_class, windows["adaptive"])}


def evaluate_change_event(ev: ChangeEvent) -> dict[str, Any]:
    forbidden = ev.event_name in FORBIDDEN_EVENT_NAMES
    pipeline_ok = ev.via_pipeline or any(p in ev.principal for p in PIPELINE_ACTORS)
    issues = []
    if forbidden and not pipeline_ok:
        issues.append(
            f"Direct modification `{ev.event_name}` by `{ev.principal}` violates KSI-CMT-RMV "
            "(redeploy from version control instead)"
        )
    if forbidden and pipeline_ok:
        # still log — some pipeline actions map to these APIs; require ticket id in production
        pass
    return {
        "event_name": ev.event_name,
        "principal": ev.principal,
        "via_pipeline": pipeline_ok,
        "status": "FAIL" if issues else "PASS",
        "issues": issues,
        "logged_for_ksi_cmt_lmc": True,
    }


def evaluate_pipeline(run: PipelineRun) -> dict[str, Any]:
    required_gates = ["iac_scan", "policy_as_code", "unit"]
    missing = [g for g in required_gates if not run.gates.get(g)]
    issues = []
    if missing:
        issues.append(f"Missing automated validation gates: {', '.join(missing)} (KSI-CMT-VTD)")
    if run.deployed and not run.post_deploy_validation:
        issues.append("Deployed without post-deploy validation (KSI-CMT-VTD)")
    if not run.commit_sha or run.commit_sha == "dirty":
        issues.append("Deploy not tied to immutable commit SHA (KSI-CMT-RMV)")
    scn = classify_scn(run.change_class)
    return {
        "pipeline_name": run.pipeline_name,
        "commit_sha": run.commit_sha,
        "status": "FAIL" if issues else "PASS",
        "issues": issues,
        "gates": run.gates,
        "scn": scn,
    }


def demo_events() -> list[ChangeEvent]:
    return [
        ChangeEvent(
            event_name="AuthorizeSecurityGroupIngress",
            event_time=datetime.now(timezone.utc).isoformat(),
            principal="arn:aws:sts::111111111111:assumed-role/HumanAdmin/alice",
            source_ip="203.0.113.10",
            user_agent="console.amazonaws.com",
            resources=["sg-0123"],
            via_pipeline=False,
        ),
        ChangeEvent(
            event_name="UpdateFunctionCode20150331v2",
            event_time=datetime.now(timezone.utc).isoformat(),
            principal="arn:aws:iam::111111111111:role/CodePipelineServiceRole",
            source_ip=None,
            user_agent="codepipeline.amazonaws.com",
            resources=["arn:aws:lambda:us-east-1:111111111111:function:api"],
            via_pipeline=True,
        ),
    ]


def demo_pipeline() -> PipelineRun:
    return PipelineRun(
        pipeline_name="federal-cso-deploy",
        commit_sha="abc123def456",
        gates={"iac_scan": True, "policy_as_code": True, "unit": True, "integration": True},
        deployed=True,
        post_deploy_validation=True,
        change_class="routine",
    )


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    changes_raw = event.get("change_events")
    changes = (
        [ChangeEvent(**c) for c in changes_raw]
        if changes_raw is not None
        else demo_events()
    )
    change_results = [evaluate_change_event(c) for c in changes]

    praw = event.get("pipeline_run")
    pipeline = (
        PipelineRun(
            pipeline_name=praw["pipeline_name"],
            commit_sha=praw["commit_sha"],
            gates=dict(praw.get("gates") or {}),
            deployed=bool(praw.get("deployed", False)),
            post_deploy_validation=bool(praw.get("post_deploy_validation", False)),
            change_class=praw.get("change_class", "routine"),
        )
        if praw
        else demo_pipeline()
    )
    pipeline_result = evaluate_pipeline(pipeline)

    failing = [r for r in change_results if r["status"] == "FAIL"]
    if pipeline_result["status"] == "FAIL":
        failing.append(pipeline_result)

    evidence = {
        "lab_id": LAB_ID,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": "FAIL" if failing else "PASS",
        "change_event_results": change_results,
        "pipeline_result": pipeline_result,
        "scp_guardrails": {
            "recommended": [
                "Deny CloudTrail StopLogging/DeleteTrail",
                "Deny security group admin from non-pipeline roles",
                "Deny iam:CreateAccessKey for humans in prod",
                "Require MFA + break-glass for emergency override",
            ],
            "intent": "Force redeploy via IaC; block direct console mutation paths (KSI-CMT-RMV)",
        },
        "procedure_review": {
            "ksi": "KSI-CMT-RVP",
            "cadence_days": 90,
            "checklist": [
                "Emergency change path documented with dual control",
                "SCN classification guide current",
                "Pipeline gates match policy-as-code pack",
                "Failed gate cannot be skipped without recorded exception",
            ],
        },
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
    }
    print(json.dumps({"status": evidence["status"], "failing": len(failing)}))
    return {"statusCode": 200, "body": json.dumps(evidence)}
