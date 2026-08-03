"""Privileged suspend + account lifecycle automation.

FedRAMP CR26:
  KSI-IAM-SUS  disable/secure privileged accounts on suspicious activity
  KSI-IAM-AAM  automate lifecycle & privileges for accounts/roles/groups
  KSI-IAM-ELP / JIT / APM  least privilege, JIT, passwordless/phishing-resistant

Handles three event classes:
  A) IdP lifecycle (joiner/mover/leaver) from Okta/Descope — ``mode=lifecycle``
  B) Suspicious privileged activity from GuardDuty/CloudTrail — ``mode=suspicious``
  C) Standing-privilege roster review — ``mode=review``

Privilege is ALWAYS computed by detection (:func:`is_privileged`). A
caller-supplied ``privileged`` field may only escalate, never de-escalate —
a GuardDuty-shaped event (which has no such field) or a tampered
``privileged: false`` still takes the suspend path when detection fires.

Suspension is real (injectable ``iam_client``): active access keys are
deactivated and a deny-all inline policy is attached to the user/role. It is
gated on ``AUTO_SUSPEND`` (default false). Status semantics are fail-closed:

  * suspension required and executed → ``PASS`` with actions listed
  * suspension required but dry-run (``AUTO_SUSPEND`` disabled) or an IAM
    call failed → ``FAIL`` with a reason, so dashboards escalate instead of
    reporting a suspended-in-name-only PASS
  * suspension not required → ``PASS`` (ticket-only)

Demo data enters only via ``{"mode": "simulation"}`` and is stamped
``data_source: simulation``.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from lab_common import (
    ConfigError,
    EvidenceWriter,
    RuntimeContext,
    Status,
    coerce_bool,
    get_bool_env,
    get_csv_env,
    get_int_env,
    get_logger,
    new_run_id,
    publish_alert,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "14-privileged-suspend-lifecycle"
SCF_CONTROLS = ["IAC-15", "IAC-16", "IAC-17", "IAC-21", "MON-01", "THR-03"]
FEDRAMP_KSI = ["KSI-IAM-SUS", "KSI-IAM-AAM", "KSI-IAM-ELP", "KSI-IAM-JIT", "KSI-IAM-APM"]

logger = get_logger(LAB_ID)

DENY_ALL_POLICY_NAME = "lab14-suspension-deny-all"
DENY_ALL_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Lab14Suspension", "Effect": "Deny", "Action": "*", "Resource": "*"}
        ],
    }
)

# Well-known privileged markers, matched as regexes (case-insensitive).
_WELL_KNOWN_PRIVILEGE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"AdministratorAccess",
        r"PowerUserAccess",
        r"FullAccess",
        r"OrganizationAccountAccessRole",
        r"Break.?Glass",
        r"SuperUser",
        r"\*:\*",
    )
]

# Name-segment heuristic (replaces the old `"admin" in blob.lower()` substring
# check that false-positived on "admin-assistant" / "readonly-admin-audit"):
# names are split on separators and camelCase; an admin-ish segment marks the
# name privileged UNLESS a read-only/audit qualifier segment is also present.
# Precise org-specific matching belongs in PRIVILEGED_ROLE_PATTERNS (csv of
# regexes).
_SEGMENT_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")
_ADMIN_SEGMENTS = {"admin", "administrator", "root", "sudo"}
_NON_PRIVILEGED_QUALIFIERS = {"readonly", "read", "audit", "auditor", "view", "viewer", "assistant"}

_IAM_USER_RE = re.compile(r"^arn:[a-z0-9-]+:iam::\d{12}:user/(?:[^/]+/)*([^/]+)$")
_IAM_ROLE_RE = re.compile(r"^arn:[a-z0-9-]+:iam::\d{12}:role/(?:[^/]+/)*([^/]+)$")
_STS_ASSUMED_ROLE_RE = re.compile(r"^arn:[a-z0-9-]+:sts::\d{12}:assumed-role/([^/]+)")


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


def _str_list_field(raw: dict[str, Any], key: str, where: str) -> list[str]:
    if key not in raw:
        return []
    value = raw[key]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(
            f"{where}: {key} must be a list of strings, got {type(value).__name__}"
        )
    return list(value)


def _name_segments(name: str) -> set[str]:
    return {s.lower() for s in _SEGMENT_RE.findall(name)}


def is_privileged(
    names: list[str], extra_patterns: list[re.Pattern[str]] | None = None
) -> bool:
    """Detect privilege from group/policy/principal names.

    Each name is checked individually (never a joined blob) against the
    well-known markers, the configured PRIVILEGED_ROLE_PATTERNS regexes, and
    the admin-segment heuristic.
    """
    for name in names:
        if any(p.search(name) for p in _WELL_KNOWN_PRIVILEGE_PATTERNS):
            return True
        if extra_patterns and any(p.search(name) for p in extra_patterns):
            return True
        segments = _name_segments(name)
        if segments & _ADMIN_SEGMENTS and not segments & _NON_PRIVILEGED_QUALIFIERS:
            return True
    return False


def compiled_privilege_patterns() -> list[re.Pattern[str]]:
    patterns: list[re.Pattern[str]] = []
    for raw in get_csv_env("PRIVILEGED_ROLE_PATTERNS", []):
        try:
            patterns.append(re.compile(raw, re.IGNORECASE))
        except re.error as exc:
            raise ConfigError(
                f"PRIVILEGED_ROLE_PATTERNS entry {raw!r} is not a valid regex: {exc}"
            ) from exc
    return patterns


def parse_iam_identity(principal: str) -> tuple[str, str] | None:
    """Reduce a principal ARN to ("user"|"role", name), or None if neither."""
    match = _IAM_USER_RE.match(principal)
    if match:
        return "user", match.group(1)
    match = _IAM_ROLE_RE.match(principal)
    if match:
        return "role", match.group(1)
    match = _STS_ASSUMED_ROLE_RE.match(principal)
    if match:
        return "role", match.group(1)
    return None


@dataclass
class LifecycleEvent:
    event_type: str  # joiner | mover | leaver
    user_id: str
    email: str = ""
    groups: list[str] = field(default_factory=list)
    privileged: bool = False  # effective — detection, escalated-only by hint
    privileged_detected: bool = False
    privileged_hint: bool | None = None
    source: str = "okta"

    @classmethod
    def from_dict(
        cls, raw: Any, extra_patterns: list[re.Pattern[str]] | None = None
    ) -> LifecycleEvent:
        if not isinstance(raw, dict):
            raise ValueError(f"lifecycle payload must be an object, got {type(raw).__name__}")
        where = "lifecycle"
        event_type = _str_field(raw, "event_type", where)
        if event_type not in ("joiner", "mover", "leaver"):
            raise ValueError(
                f"{where}: event_type must be joiner|mover|leaver, got {event_type!r}"
            )
        user_id = _str_field(raw, "user_id", where)
        if not user_id:
            raise ValueError(f"{where}: user_id must be a non-empty string")
        groups = _str_list_field(raw, "groups", where)
        detected = is_privileged(groups, extra_patterns)
        hint = coerce_bool(raw.get("privileged"))
        return cls(
            event_type=event_type,
            user_id=user_id,
            email=_str_field(raw, "email", where, required=False),
            groups=groups,
            # Detection is authoritative; an event hint may only escalate.
            privileged=detected or hint is True,
            privileged_detected=detected,
            privileged_hint=hint,
            source=_str_field(raw, "source", where, required=False, default="okta"),
        )


@dataclass
class SuspiciousEvent:
    finding_type: str
    principal: str
    severity: str = "UNKNOWN"
    detail: str = ""
    privileged: bool = False  # effective — detection, escalated-only by hint
    privileged_detected: bool = False
    privileged_hint: bool | None = None
    source: str = "guardduty"

    @classmethod
    def from_dict(
        cls, raw: Any, extra_patterns: list[re.Pattern[str]] | None = None
    ) -> SuspiciousEvent:
        if not isinstance(raw, dict):
            raise ValueError(f"suspicious payload must be an object, got {type(raw).__name__}")
        where = "suspicious"
        principal = _str_field(raw, "principal", where)
        if not principal:
            raise ValueError(f"{where}: principal must be a non-empty string")
        detected = is_privileged([principal], extra_patterns)
        hint = coerce_bool(raw.get("privileged"))
        return cls(
            finding_type=_str_field(raw, "finding_type", where),
            principal=principal,
            severity=_str_field(raw, "severity", where, required=False, default="UNKNOWN").upper(),
            detail=_str_field(raw, "detail", where, required=False),
            # Detection is authoritative; `privileged: false` from the event
            # (or a GuardDuty event lacking the field) never de-escalates.
            privileged=detected or hint is True,
            privileged_detected=detected,
            privileged_hint=hint,
            source=_str_field(raw, "source", where, required=False, default="guardduty"),
        )


@dataclass
class ActionResult:
    action: str
    target: str
    status: str  # RECORDED | SUSPENDED | DRY_RUN | FAILED
    detail: str


def apply_lifecycle(ev: LifecycleEvent) -> list[ActionResult]:
    actions: list[ActionResult] = []
    if ev.event_type == "joiner":
        actions.append(
            ActionResult(
                "provision_idp_to_idc",
                ev.user_id,
                "RECORDED",
                "Create/enable Identity Center user; assign least-privilege permission sets only",
            )
        )
        if ev.privileged:
            actions.append(
                ActionResult(
                    "require_jit_and_phishing_resistant_mfa",
                    ev.user_id,
                    "RECORDED",
                    "Privileged joiner must use JIT elevation + WebAuthn/PIV (KSI-IAM-JIT/APM)",
                )
            )
    elif ev.event_type == "mover":
        actions.append(
            ActionResult(
                "reconcile_groups_permission_sets",
                ev.user_id,
                "RECORDED",
                f"Diff groups={ev.groups}; revoke stale privileged sets",
            )
        )
    elif ev.event_type == "leaver":
        actions.extend(
            [
                ActionResult("disable_idp_user", ev.user_id, "RECORDED", "Disable Okta/Descope user"),
                ActionResult("revoke_idc_sessions", ev.user_id, "RECORDED", "Revoke active IDC sessions"),
                ActionResult("disable_iam_keys", ev.user_id, "RECORDED", "Disable any IAM user keys"),
                ActionResult(
                    "remove_from_privileged_groups",
                    ev.user_id,
                    "RECORDED",
                    "Remove admin/break-glass group memberships immediately",
                ),
            ]
        )
    else:  # pragma: no cover - from_dict validates event_type
        raise ValueError(f"unknown lifecycle event_type {ev.event_type!r}")
    return actions


def _post_suspend_actions(ev: SuspiciousEvent, break_glass_role: str) -> list[ActionResult]:
    return [
        ActionResult(
            "open_break_glass_ticket",
            break_glass_role,
            "RECORDED",
            "Notify SOC; re-enable only via break-glass with MFA + dual control",
        ),
        ActionResult(
            "preserve_forensic_evidence",
            ev.principal,
            "RECORDED",
            "Snapshot CloudTrail/GuardDuty context into evidence bucket",
        ),
    ]


def dry_run_suspension(ev: SuspiciousEvent, break_glass_role: str) -> list[ActionResult]:
    return [
        ActionResult(
            "deactivate_access_keys",
            ev.principal,
            "DRY_RUN",
            "Would deactivate all active IAM access keys (AUTO_SUSPEND disabled)",
        ),
        ActionResult(
            "attach_deny_all_policy",
            ev.principal,
            "DRY_RUN",
            f"Would attach inline deny-all policy {DENY_ALL_POLICY_NAME} (AUTO_SUSPEND disabled)",
        ),
        *_post_suspend_actions(ev, break_glass_role),
    ]


def execute_suspension(
    ev: SuspiciousEvent, iam_client: Any, break_glass_role: str
) -> tuple[list[ActionResult], bool]:
    """KSI-IAM-SUS — real suspend: deactivate keys + attach deny-all policy.

    Returns (actions, ok). A failed IAM call surfaces as a FAILED action and
    ok=False so the handler reports FAIL — never a silent PASS.
    """
    identity = parse_iam_identity(ev.principal)
    if identity is None:
        return (
            [
                ActionResult(
                    "suspend_principal",
                    ev.principal,
                    "FAILED",
                    "cannot derive an IAM user/role identity from principal ARN",
                )
            ],
            False,
        )
    kind, name = identity
    actions: list[ActionResult] = []
    ok = True
    try:
        if kind == "user":
            keys = iam_client.list_access_keys(UserName=name).get("AccessKeyMetadata", [])
            for key in keys:
                if key.get("Status") != "Active":
                    continue
                iam_client.update_access_key(
                    UserName=name, AccessKeyId=key["AccessKeyId"], Status="Inactive"
                )
                actions.append(
                    ActionResult(
                        "deactivate_access_key",
                        key["AccessKeyId"],
                        "SUSPENDED",
                        f"Access key for user {name} set Inactive",
                    )
                )
            iam_client.put_user_policy(
                UserName=name,
                PolicyName=DENY_ALL_POLICY_NAME,
                PolicyDocument=DENY_ALL_POLICY,
            )
            actions.append(
                ActionResult(
                    "attach_deny_all_policy",
                    name,
                    "SUSPENDED",
                    f"Inline deny-all attached to user {name} due to "
                    f"{ev.finding_type} severity={ev.severity}",
                )
            )
        else:
            iam_client.put_role_policy(
                RoleName=name,
                PolicyName=DENY_ALL_POLICY_NAME,
                PolicyDocument=DENY_ALL_POLICY,
            )
            actions.append(
                ActionResult(
                    "attach_deny_all_policy",
                    name,
                    "SUSPENDED",
                    f"Inline deny-all attached to role {name} due to "
                    f"{ev.finding_type} severity={ev.severity}",
                )
            )
    except Exception as exc:  # noqa: BLE001 - a failed suspend must surface as FAIL, not crash
        actions.append(
            ActionResult("suspend_principal", ev.principal, "FAILED", f"suspend action raised: {exc}")
        )
        ok = False
    actions.extend(_post_suspend_actions(ev, break_glass_role))
    return actions, ok


def periodic_privilege_review(
    roster: list[Any], max_standing_days: int
) -> dict[str, Any]:
    """KSI-IAM-AAM / IAC-17 — standing privilege detection."""
    standing = []
    for idx, row in enumerate(roster):
        if not isinstance(row, dict):
            raise ValueError(f"roster row {idx} must be an object, got {type(row).__name__}")
        age_raw = row.get("privileged_standing_days", 0)
        try:
            age = float(age_raw or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"roster row {idx}: privileged_standing_days must be numeric, got {age_raw!r}"
            ) from exc
        if coerce_bool(row.get("privileged")) is True and age > max_standing_days:
            standing.append(row)
    return {
        "reviewed_count": len(roster),
        "standing_privileged_violations": standing,
        "status": "PASS" if not standing else "FAIL",
        "policy_max_standing_days": max_standing_days,
        "preferred_model": "JIT elevation with time-boxed permission sets",
    }


def _simulation_suspicious() -> dict[str, Any]:
    # Deliberately GuardDuty-shaped: no `privileged` field — detection decides.
    return {
        "finding_type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
        "principal": "arn:aws:iam::123456789012:role/AdminRole",
        "severity": "HIGH",
        "detail": "simulated suspicious privileged activity",
    }


def _resolve_mode(event: dict[str, Any]) -> str:
    mode = event.get("mode") or (
        "lifecycle"
        if "lifecycle" in event
        else "suspicious"
        if "suspicious" in event
        else "review"
        if "roster" in event
        else None
    )
    if mode not in ("lifecycle", "suspicious", "review"):
        raise ValueError(
            "cannot determine mode: provide mode=lifecycle|suspicious|review with its "
            "payload (`lifecycle` object, `suspicious` object, or `roster` list), "
            "or {'mode': 'simulation'}"
        )
    return mode


def handler(
    event: dict[str, Any],
    context: Any,
    iam_client: Any = None,
    s3_client: Any = None,
    sns_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        RuntimeContext.from_lambda(context)  # fail closed if we can't tell where we run

        auto_suspend = get_bool_env("AUTO_SUSPEND", default=False)
        break_glass_role = os.environ.get("BREAK_GLASS_ROLE", "BreakGlassAdmin")
        max_standing_days = get_int_env("MAX_STANDING_PRIV_DAYS", default=1)
        extra_patterns = compiled_privilege_patterns()

        if simulation_requested(event):
            data_source = "simulation"
            mode = "suspicious"
            suspicious_raw: Any = event.get("suspicious") or _simulation_suspicious()
        else:
            data_source = "event"
            mode = _resolve_mode(event)
            suspicious_raw = event.get("suspicious")

        actions: list[ActionResult] = []
        detail: dict[str, Any] = {}
        status = Status.PASS
        fail_reason: str | None = None
        suspension_required = False

        if mode == "lifecycle":
            raw = event.get("lifecycle")
            if not isinstance(raw, dict):
                raise ValueError("mode=lifecycle requires a `lifecycle` payload object")
            lev = LifecycleEvent.from_dict(raw, extra_patterns)
            actions = apply_lifecycle(lev)
            detail = {"lifecycle": asdict(lev)}
        elif mode == "suspicious":
            sev = SuspiciousEvent.from_dict(suspicious_raw, extra_patterns)
            suspension_required = sev.privileged
            if not suspension_required:
                actions = [
                    ActionResult(
                        "ticket_only",
                        sev.principal,
                        "RECORDED",
                        "Non-privileged anomaly — open ticket; do not auto-suspend",
                    )
                ]
            elif not auto_suspend:
                actions = dry_run_suspension(sev, break_glass_role)
                status = Status.FAIL
                fail_reason = "suspension required but AUTO_SUSPEND disabled (dry-run only)"
            else:
                if iam_client is None:  # pragma: no cover - AWS only
                    import boto3

                    iam_client = boto3.client("iam")
                actions, suspend_ok = execute_suspension(sev, iam_client, break_glass_role)
                if not suspend_ok:
                    status = Status.FAIL
                    fail_reason = "suspension required but one or more suspend actions failed"
            detail = {"suspicious": asdict(sev)}
        else:  # review
            roster = event.get("roster")
            if not isinstance(roster, list):
                raise ValueError("mode=review requires a `roster` list payload")
            review = periodic_privilege_review(roster, max_standing_days)
            detail = {"privilege_review": review}
            if review["status"] == "FAIL":
                status = Status.FAIL
                fail_reason = (
                    f"{len(review['standing_privileged_violations'])} standing-privilege "
                    f"violation(s) beyond {max_standing_days} day(s)"
                )

        suspend_done = any(a.status == "SUSPENDED" for a in actions)

        evidence = {
            "lab_id": LAB_ID,
            "checked_at": utc_now().isoformat(),
            "status": status.value,
            "mode": mode,
            "data_source": data_source,
            "actions": [asdict(a) for a in actions],
            "auto_suspend_enabled": auto_suspend,
            "suspension_required": suspension_required,
            "privileged_suspend_executed": suspend_done,
            "fail_reason": fail_reason,
            "max_standing_priv_days": max_standing_days,
            "detail": detail,
            "control_objectives": {
                "KSI-IAM-SUS": "Privileged principals are disabled/secured on suspicious activity",
                "KSI-IAM-AAM": "Joiner/mover/leaver and privilege changes are automated",
                "KSI-IAM-JIT": "Standing privilege beyond policy max days fails review",
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
                fail_reason or f"{mode} check reported {status.value}",
                sns_client=sns_client,
            )
        logger.info(
            "privileged lifecycle check complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "mode": mode,
                "actions": len(actions),
                "suspension_required": suspension_required,
                "suspend_executed": suspend_done,
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
