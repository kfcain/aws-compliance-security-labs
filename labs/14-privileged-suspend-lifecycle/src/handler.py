"""
Privileged suspend + account lifecycle automation.

FedRAMP CR26:
  KSI-IAM-SUS  disable/secure privileged accounts on suspicious activity
  KSI-IAM-AAM  automate lifecycle & privileges for accounts/roles/groups
  KSI-IAM-ELP / JIT / APM  least privilege, JIT, passwordless/phishing-resistant

Handles two event classes:
  A) IdP lifecycle (joiner/mover/leaver) from Okta/Descope
  B) Suspicious privileged activity from GuardDuty/CloudTrail
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

LAB_ID = "14-privileged-suspend-lifecycle"
SCF_CONTROLS = ["IAC-15", "IAC-16", "IAC-17", "IAC-21", "MON-01", "THR-03"]
FEDRAMP_KSI = ["KSI-IAM-SUS", "KSI-IAM-AAM", "KSI-IAM-ELP", "KSI-IAM-JIT", "KSI-IAM-APM"]

PRIVILEGED_PERMISSION_MARKERS = [
    "AdministratorAccess",
    "PowerUserAccess",
    "IAMFullAccess",
    "OrganizationAccountAccessRole",
    "*:*",
]
AUTO_SUSPEND = os.environ.get("AUTO_SUSPEND", "true").lower() == "true"
BREAK_GLASS_ROLE = os.environ.get("BREAK_GLASS_ROLE", "BreakGlassAdmin")


@dataclass
class LifecycleEvent:
    event_type: str  # joiner | mover | leaver
    user_id: str
    email: str
    groups: list[str] = field(default_factory=list)
    privileged: bool = False
    source: str = "okta"


@dataclass
class SuspiciousEvent:
    finding_type: str
    principal: str
    privileged: bool
    severity: str
    detail: str
    source: str = "guardduty"


@dataclass
class ActionResult:
    action: str
    target: str
    status: str
    detail: str


def is_privileged(groups_or_policies: list[str]) -> bool:
    blob = " ".join(groups_or_policies)
    return any(m in blob for m in PRIVILEGED_PERMISSION_MARKERS) or "admin" in blob.lower()


def apply_lifecycle(ev: LifecycleEvent) -> list[ActionResult]:
    actions: list[ActionResult] = []
    if ev.event_type == "joiner":
        actions.append(
            ActionResult(
                "provision_idp_to_idc",
                ev.user_id,
                "OK_PLACEHOLDER",
                "Create/enable Identity Center user; assign least-privilege permission sets only",
            )
        )
        if ev.privileged:
            actions.append(
                ActionResult(
                    "require_jit_and_phishing_resistant_mfa",
                    ev.user_id,
                    "OK_PLACEHOLDER",
                    "Privileged joiner must use JIT elevation + WebAuthn/PIV (KSI-IAM-JIT/APM)",
                )
            )
    elif ev.event_type == "mover":
        actions.append(
            ActionResult(
                "reconcile_groups_permission_sets",
                ev.user_id,
                "OK_PLACEHOLDER",
                f"Diff groups={ev.groups}; revoke stale privileged sets",
            )
        )
    elif ev.event_type == "leaver":
        actions.extend(
            [
                ActionResult("disable_idp_user", ev.user_id, "OK_PLACEHOLDER", "Disable Okta/Descope user"),
                ActionResult("revoke_idc_sessions", ev.user_id, "OK_PLACEHOLDER", "Revoke active IDC sessions"),
                ActionResult("disable_iam_keys", ev.user_id, "OK_PLACEHOLDER", "Disable any IAM user keys"),
                ActionResult(
                    "remove_from_privileged_groups",
                    ev.user_id,
                    "OK_PLACEHOLDER",
                    "Remove admin/break-glass group memberships immediately",
                ),
            ]
        )
    else:
        actions.append(ActionResult("noop", ev.user_id, "ERROR", f"unknown event_type {ev.event_type}"))
    return actions


def apply_suspicious(ev: SuspiciousEvent) -> list[ActionResult]:
    actions: list[ActionResult] = []
    if not ev.privileged:
        actions.append(
            ActionResult(
                "ticket_only",
                ev.principal,
                "OK_PLACEHOLDER",
                "Non-privileged anomaly — open ticket; do not auto-suspend",
            )
        )
        return actions

    if not AUTO_SUSPEND:
        actions.append(
            ActionResult("manual_review_required", ev.principal, "WARN", "AUTO_SUSPEND=false")
        )
        return actions

    # KSI-IAM-SUS — disable or otherwise secure privileged access
    actions.extend(
        [
            ActionResult(
                "disable_privileged_permission_sets",
                ev.principal,
                "SUSPENDED_PLACEHOLDER",
                f"Auto-suspend due to {ev.finding_type} severity={ev.severity}",
            ),
            ActionResult(
                "revoke_active_sessions",
                ev.principal,
                "SUSPENDED_PLACEHOLDER",
                "Revoke IDC/IAM sessions and temporary credentials",
            ),
            ActionResult(
                "open_break_glass_ticket",
                BREAK_GLASS_ROLE,
                "OK_PLACEHOLDER",
                "Notify SOC; re-enable only via break-glass with MFA + dual control",
            ),
            ActionResult(
                "preserve_forensic_evidence",
                ev.principal,
                "OK_PLACEHOLDER",
                "Snapshot CloudTrail/Guage context into evidence bucket",
            ),
        ]
    )
    return actions


def periodic_privilege_review(roster: list[dict[str, Any]]) -> dict[str, Any]:
    """KSI-IAM-AAM / IAC-17 — standing privilege detection."""
    standing = []
    for row in roster:
        age = float(row.get("privileged_standing_days") or 0)
        if row.get("privileged") and age > float(os.environ.get("MAX_STANDING_PRIV_DAYS", "1")):
            standing.append(row)
    return {
        "reviewed_count": len(roster),
        "standing_privileged_violations": standing,
        "status": "PASS" if not standing else "FAIL",
        "policy_max_standing_days": os.environ.get("MAX_STANDING_PRIV_DAYS", "1"),
        "preferred_model": "JIT elevation with time-boxed permission sets",
    }


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    mode = event.get("mode") or (
        "lifecycle" if "lifecycle" in event else "suspicious" if "suspicious" in event else "review"
    )
    actions: list[ActionResult] = []
    detail: dict[str, Any] = {}

    if mode == "lifecycle":
        raw = event["lifecycle"]
        ev = LifecycleEvent(
            event_type=raw["event_type"],
            user_id=raw["user_id"],
            email=raw.get("email", ""),
            groups=list(raw.get("groups") or []),
            privileged=bool(raw.get("privileged", is_privileged(raw.get("groups") or []))),
            source=raw.get("source", "okta"),
        )
        actions = apply_lifecycle(ev)
        detail = {"lifecycle": asdict(ev)}
    elif mode == "suspicious":
        raw = event.get("suspicious") or {
            "finding_type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
            "principal": "arn:aws:iam::123:role/AdminRole",
            "privileged": True,
            "severity": "HIGH",
            "detail": "demo suspicious privileged activity",
        }
        ev = SuspiciousEvent(**raw)
        actions = apply_suspicious(ev)
        detail = {"suspicious": asdict(ev)}
    else:
        roster = event.get("roster") or [
            {"user_id": "u-admin", "privileged": True, "privileged_standing_days": 30},
            {"user_id": "u-jit", "privileged": True, "privileged_standing_days": 0.2},
        ]
        detail = {"privilege_review": periodic_privilege_review(roster)}

    review_status = detail.get("privilege_review", {}).get("status")
    suspend_done = any(a.status.startswith("SUSPENDED") for a in actions)
    status = "PASS"
    if review_status == "FAIL":
        status = "FAIL"
    if any(a.status == "ERROR" for a in actions):
        status = "ERROR"

    evidence = {
        "lab_id": LAB_ID,
        "checked_at": datetime.now(UTC).isoformat(),
        "status": status,
        "mode": mode,
        "actions": [asdict(a) for a in actions],
        "auto_suspend_enabled": AUTO_SUSPEND,
        "privileged_suspend_executed": suspend_done,
        "detail": detail,
        "control_objectives": {
            "KSI-IAM-SUS": "Privileged principals are disabled/secured on suspicious activity",
            "KSI-IAM-AAM": "Joiner/mover/leaver and privilege changes are automated",
            "KSI-IAM-JIT": "Standing privilege beyond policy max days fails review",
        },
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
    }
    print(json.dumps({"status": status, "mode": mode, "actions": len(actions)}))
    return {"statusCode": 200, "body": json.dumps(evidence)}
