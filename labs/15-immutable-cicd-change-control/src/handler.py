"""Immutable CI/CD change control & deployment validation.

FedRAMP CR26:
  KSI-CMT-RMV  redeploy version-controlled resources vs direct modification
  KSI-CMT-VTD  automated validation throughout deployment
  KSI-CMT-LMC  log/monitor modifications to the CSO
  KSI-CMT-RVP  review change procedures
  KSI-AFR-SCN  classify significant changes (routine/adaptive/transformative)

Detects forbidden in-place change paths and evaluates pipeline gate evidence.

Pipeline-actor decision (the control this lab exists to enforce):
  * Any ``via_pipeline`` field on the event is IGNORED for the decision — a
    caller-supplied boolean must never defeat the control (it is recorded as
    ``claimed_via_pipeline`` for forensics only).
  * The principal is normalized — an STS assumed-role ARN reduces to its
    underlying (account_id, role_name) — and compared EXACTLY against the
    role ARNs configured in ``PIPELINE_ACTOR_ROLE_ARNS`` (csv of full IAM
    role ARNs). Substring matching previously passed
    ``role/CodePipelineServiceRoleShadow`` and cross-account lookalikes.
  * ``PIPELINE_ACTOR_ROLE_ARNS`` unset → ``CONFIG_ERROR``; there is no
    hardcoded default account.

Forbidden APIs invoked *by* a pipeline actor are recorded as findings that
require change-ticket correlation (KSI-CMT-RVP): with a ``change_ticket`` on
the event they are INFO findings; without one they are MEDIUM violations and
fail the control.

Demo data enters only via ``{"mode": "simulation"}`` and is stamped
``data_source: simulation``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from lab_common import (
    ConfigError,
    EvidenceWriter,
    RuntimeContext,
    Status,
    coerce_bool,
    get_csv_env,
    get_logger,
    new_run_id,
    parse_iso8601,
    publish_alert,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "15-immutable-cicd-change-control"
SCF_CONTROLS = ["CHG-01", "CHG-02", "CHG-03", "CHG-04", "CFG-01", "TDA-06"]
FEDRAMP_KSI = ["KSI-CMT-RMV", "KSI-CMT-VTD", "KSI-CMT-LMC", "KSI-CMT-RVP", "KSI-AFR-SCN"]

logger = get_logger(LAB_ID)

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

_ROLE_ARN_RE = re.compile(r"^arn:[a-z0-9-]+:iam::(\d{12}):role/(?:[^/]+/)*([^/]+)$")
_ASSUMED_ROLE_RE = re.compile(r"^arn:[a-z0-9-]+:sts::(\d{12}):assumed-role/([^/]+)")
_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")


def _str_field(
    raw: dict[str, Any], key: str, where: str, *, required: bool = True, default: str = ""
) -> str:
    if key not in raw:
        if required:
            raise ValueError(f"{where}: missing required key {key!r}")
        return default
    value = raw[key]
    if not isinstance(value, str):
        raise ValueError(f"{where}: {key} must be a string, got {type(value).__name__}")
    return value


def _opt_str_field(raw: dict[str, Any], key: str, where: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{where}: {key} must be a string, got {type(value).__name__}")
    return value


def _bool_field(raw: dict[str, Any], key: str, where: str, default: bool) -> bool:
    if key not in raw:
        return default
    value = coerce_bool(raw[key])
    if value is None:
        raise ValueError(f"{where}: {key} must be a boolean, got {raw[key]!r}")
    return value


def normalize_principal(principal: str) -> tuple[str, str] | None:
    """Reduce a principal ARN to its underlying (account_id, role_name).

    * IAM role ARN  ``arn:…:iam::acct:role/path/Name``            → (acct, Name)
    * STS assumed-role ``arn:…:sts::acct:assumed-role/Name/sess`` → (acct, Name)

    Anything else (IAM users, service principals, unparseable strings) is not
    a pipeline actor. Comparison against the configured set is EXACT on the
    tuple — substring matching allowed ``…role/CodePipelineServiceRoleShadow``
    and same-name roles in foreign accounts through the control.
    """
    match = _ROLE_ARN_RE.match(principal)
    if match:
        return match.group(1), match.group(2)
    match = _ASSUMED_ROLE_RE.match(principal)
    if match:
        return match.group(1), match.group(2)
    return None


def load_pipeline_roles() -> tuple[set[tuple[str, str]], list[str]]:
    """Parse PIPELINE_ACTOR_ROLE_ARNS (required; csv of full IAM role ARNs)."""
    arns = get_csv_env("PIPELINE_ACTOR_ROLE_ARNS")
    roles: set[tuple[str, str]] = set()
    for arn in arns:
        match = _ROLE_ARN_RE.match(arn)
        if not match:
            raise ConfigError(
                f"PIPELINE_ACTOR_ROLE_ARNS entry {arn!r} is not a full IAM role ARN "
                "(expected arn:<partition>:iam::<account-id>:role/<name>)"
            )
        roles.add((match.group(1), match.group(2)))
    return roles, arns


@dataclass
class ChangeEvent:
    event_name: str
    event_time: str
    principal: str
    source_ip: str | None = None
    user_agent: str | None = None
    resources: list[str] = field(default_factory=list)
    change_ticket: str | None = None
    # Recorded for forensics only — NEVER used for the control decision.
    claimed_via_pipeline: bool | None = None

    @classmethod
    def from_dict(cls, raw: Any) -> ChangeEvent:
        """Validated construction — never ``ChangeEvent(**raw)``.

        Unknown keys are ignored; wrong types raise ValueError with a clear
        message. ``event_time`` is normalized through ``parse_iso8601``.
        """
        if not isinstance(raw, dict):
            raise ValueError(f"change event must be an object, got {type(raw).__name__}")
        where = "change event"
        event_name = _str_field(raw, "event_name", where)
        where = f"change event {event_name!r}"
        time_raw = _str_field(raw, "event_time", where)
        try:
            event_time = parse_iso8601(time_raw).isoformat()
        except ValueError as exc:
            raise ValueError(f"{where}: event_time is not ISO-8601: {time_raw!r}") from exc
        principal = _str_field(raw, "principal", where)
        if not principal:
            raise ValueError(f"{where}: principal must be a non-empty string")
        resources_raw = raw.get("resources") or []
        if not isinstance(resources_raw, list) or not all(
            isinstance(r, str) for r in resources_raw
        ):
            raise ValueError(f"{where}: resources must be a list of strings")
        return cls(
            event_name=event_name,
            event_time=event_time,
            principal=principal,
            source_ip=_opt_str_field(raw, "source_ip", where),
            user_agent=_opt_str_field(raw, "user_agent", where),
            resources=list(resources_raw),
            change_ticket=_opt_str_field(raw, "change_ticket", where),
            claimed_via_pipeline=coerce_bool(raw.get("via_pipeline")),
        )


@dataclass
class PipelineRun:
    pipeline_name: str
    commit_sha: str
    gates: dict[str, bool]  # sast|iac_scan|unit|integration|policy_as_code
    deployed: bool
    post_deploy_validation: bool
    change_class: str  # routine | adaptive | transformative

    @classmethod
    def from_dict(cls, raw: Any) -> PipelineRun:
        """Validated construction — no ``praw["…"]`` KeyErrors."""
        if not isinstance(raw, dict):
            raise ValueError(f"pipeline_run must be an object, got {type(raw).__name__}")
        where = "pipeline_run"
        gates_raw = raw.get("gates") or {}
        if not isinstance(gates_raw, dict):
            raise ValueError(f"{where}: gates must be an object, got {type(gates_raw).__name__}")
        gates: dict[str, bool] = {}
        for name, value in gates_raw.items():
            passed = coerce_bool(value)
            if passed is None:
                raise ValueError(f"{where}: gate {name!r} must be a boolean, got {value!r}")
            gates[str(name)] = passed
        return cls(
            pipeline_name=_str_field(raw, "pipeline_name", where),
            commit_sha=_str_field(raw, "commit_sha", where),
            gates=gates,
            deployed=_bool_field(raw, "deployed", where, default=False),
            post_deploy_validation=_bool_field(
                raw, "post_deploy_validation", where, default=False
            ),
            change_class=_str_field(raw, "change_class", where, required=False, default="routine"),
        )


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


def evaluate_change_event(
    ev: ChangeEvent, pipeline_roles: set[tuple[str, str]]
) -> dict[str, Any]:
    forbidden = ev.event_name in FORBIDDEN_EVENT_NAMES
    identity = normalize_principal(ev.principal)
    pipeline_ok = identity is not None and identity in pipeline_roles

    violations: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    if forbidden and not pipeline_ok:
        violations.append(
            {
                "code": "direct-modification",
                "severity": "HIGH",
                "detail": (
                    f"Direct modification `{ev.event_name}` by `{ev.principal}` violates "
                    "KSI-CMT-RMV (redeploy from version control instead)"
                ),
            }
        )
    if forbidden and pipeline_ok:
        # Pipeline actions can legitimately map to these APIs, but only under
        # a correlated change ticket (KSI-CMT-RVP). No ticket → violation.
        if ev.change_ticket:
            findings.append(
                {
                    "code": "pipeline-forbidden-api-correlated",
                    "severity": "INFO",
                    "detail": (
                        f"Pipeline-driven `{ev.event_name}` correlated to change ticket "
                        f"{ev.change_ticket} (KSI-CMT-RVP)"
                    ),
                }
            )
        else:
            violations.append(
                {
                    "code": "pipeline-forbidden-api-uncorrelated",
                    "severity": "MEDIUM",
                    "detail": (
                        f"Pipeline-driven `{ev.event_name}` has no change ticket — "
                        "requires change-ticket correlation (KSI-CMT-RVP)"
                    ),
                }
            )
    return {
        "event_name": ev.event_name,
        "event_time": ev.event_time,
        "principal": ev.principal,
        "principal_identity": (
            {"account_id": identity[0], "role_name": identity[1]} if identity else None
        ),
        "via_pipeline": pipeline_ok,
        "claimed_via_pipeline": ev.claimed_via_pipeline,
        "change_ticket": ev.change_ticket,
        "status": "FAIL" if violations else "PASS",
        "violations": violations,
        "findings": findings,
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
    if not _COMMIT_SHA_RE.fullmatch(run.commit_sha):
        issues.append(
            f"Deploy not tied to immutable commit SHA — got {run.commit_sha!r}, "
            "expected 7-40 lowercase hex chars (KSI-CMT-RMV)"
        )
    scn = classify_scn(run.change_class)
    return {
        "pipeline_name": run.pipeline_name,
        "commit_sha": run.commit_sha,
        "change_class": run.change_class,
        "status": "FAIL" if issues else "PASS",
        "issues": issues,
        "gates": run.gates,
        "scn": scn,
    }


def demo_events() -> list[ChangeEvent]:
    return [
        ChangeEvent(
            event_name="AuthorizeSecurityGroupIngress",
            event_time=utc_now().isoformat(),
            principal="arn:aws:sts::111111111111:assumed-role/HumanAdmin/alice",
            source_ip="203.0.113.10",
            user_agent="console.amazonaws.com",
            resources=["sg-0123"],
        ),
        ChangeEvent(
            event_name="UpdateFunctionCode20150331v2",
            event_time=utc_now().isoformat(),
            principal="arn:aws:iam::111111111111:role/CodePipelineServiceRole",
            user_agent="codepipeline.amazonaws.com",
            resources=["arn:aws:lambda:us-east-1:111111111111:function:api"],
            change_ticket="CHG-1234",
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


def handler(
    event: dict[str, Any],
    context: Any,
    s3_client: Any = None,
    sns_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        RuntimeContext.from_lambda(context)  # fail closed if we can't tell where we run
        pipeline_roles, pipeline_role_arns = load_pipeline_roles()

        pipeline: PipelineRun | None
        if simulation_requested(event):
            data_source = "simulation"
            changes = demo_events()
            pipeline = demo_pipeline()
        else:
            data_source = "event"
            changes_raw = event.get("change_events")
            praw = event.get("pipeline_run")
            if changes_raw is None and praw is None:
                raise ValueError(
                    "event must include `change_events` and/or `pipeline_run` "
                    "(or {'mode': 'simulation'})"
                )
            if changes_raw is not None and not isinstance(changes_raw, list):
                raise ValueError(
                    f"change_events must be a list, got {type(changes_raw).__name__}"
                )
            changes = [ChangeEvent.from_dict(c) for c in (changes_raw or [])]
            pipeline = PipelineRun.from_dict(praw) if praw is not None else None

        change_results = [evaluate_change_event(c, pipeline_roles) for c in changes]
        pipeline_result = evaluate_pipeline(pipeline) if pipeline is not None else None

        # Homogeneous lists — the pipeline result is never appended into the
        # change-event list; each population has its own evidence field.
        failing_changes = [r for r in change_results if r["status"] == "FAIL"]
        pipeline_status = pipeline_result["status"] if pipeline_result else "NOT_EVALUATED"
        status = (
            Status.FAIL if failing_changes or pipeline_status == "FAIL" else Status.PASS
        )

        evidence = {
            "lab_id": LAB_ID,
            "checked_at": utc_now().isoformat(),
            "status": status.value,
            "data_source": data_source,
            "pipeline_actor_role_arns": pipeline_role_arns,
            "change_event_results": change_results,
            "failing_change_events": failing_changes,
            "pipeline_result": pipeline_result,
            "pipeline_status": pipeline_status,
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
        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is not Status.PASS:
            publish_alert(
                LAB_ID,
                status,
                f"{len(failing_changes)} change-control violation(s); "
                f"pipeline status {pipeline_status}",
                sns_client=sns_client,
            )
        logger.info(
            "change control evaluation complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "change_events": len(change_results),
                "failing_change_events": len(failing_changes),
                "pipeline_status": pipeline_status,
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
