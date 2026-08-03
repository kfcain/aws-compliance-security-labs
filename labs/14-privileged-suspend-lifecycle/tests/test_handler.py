"""Regression + behavior tests for lab 14 (privileged suspend & lifecycle).

Headline regressions: a caller-supplied ``privileged`` flag previously
OVERRODE detection (privileged:false suppressed suspension), and the computed
``suspend_done`` never influenced the reported status (a suspended active
compromise reported PASS).
"""
from __future__ import annotations

import json

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("14-privileged-suspend-lifecycle")

ADMIN_ROLE = "arn:aws:iam::123456789012:role/AdministratorAccess"


def _invoke(event, lambda_context, iam=None):
    iam = iam or FakeClient(responses={
        "list_access_keys": {"AccessKeyMetadata": [{"AccessKeyId": "AKIAX", "Status": "Active"}]},
        "update_access_key": {},
        "put_user_policy": {},
        "put_role_policy": {},
    })
    s3, sns = FakeClient(), FakeClient()
    result = handler_mod.handler(event, lambda_context, iam_client=iam, s3_client=s3, sns_client=sns)
    return result, iam, s3, sns


def _suspicious(principal=ADMIN_ROLE, **kw):
    return {
        "finding_type": "UnauthorizedAccess:IAMUser/AnomalousBehavior",
        "principal": principal,
        "severity": "HIGH",
        **kw,
    }


def test_guardduty_event_suspends_despite_privileged_false(lambda_context, monkeypatch):
    """Regression: `privileged: false` from the event suppressed suspension of
    an obviously privileged principal."""
    monkeypatch.setenv("AUTO_SUSPEND", "true")
    event = {"mode": "suspicious", "suspicious": _suspicious(privileged=False)}
    result, iam, *_ = _invoke(event, lambda_context)
    body = json.loads(result["body"])
    assert body["suspension_required"] is True
    assert body["privileged_suspend_executed"] is True
    assert iam.calls_to("put_role_policy"), "deny-all must be attached to the role"
    assert result["compliance_status"] == "PASS"


def test_privileged_hint_can_escalate(lambda_context, monkeypatch):
    """A privileged:true hint on a principal detection misses still suspends."""
    monkeypatch.setenv("AUTO_SUSPEND", "true")
    event = {"mode": "suspicious", "suspicious": _suspicious(
        principal="arn:aws:iam::123456789012:role/quiet-service-role", privileged=True,
    )}
    result, *_ = _invoke(event, lambda_context)
    body = json.loads(result["body"])
    assert body["suspension_required"] is True


def test_suspend_failure_is_fail(lambda_context, monkeypatch):
    """Regression: suspend_done was never consulted — failed IAM calls still
    reported PASS."""
    monkeypatch.setenv("AUTO_SUSPEND", "true")
    iam = FakeClient(responses={"put_role_policy": RuntimeError("AccessDenied")})
    event = {"mode": "suspicious", "suspicious": _suspicious()}
    result, _, _, sns = _invoke(event, lambda_context, iam=iam)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert body["privileged_suspend_executed"] is False
    assert sns.calls_to("publish")


def test_dry_run_lists_actions_and_fails(lambda_context):
    """AUTO_SUSPEND default false: required suspension in dry-run is a FAIL so
    dashboards escalate — never a green check on an active compromise."""
    event = {"mode": "suspicious", "suspicious": _suspicious()}
    result, iam, _, sns = _invoke(event, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert body["fail_reason"].startswith("suspension required but AUTO_SUSPEND disabled")
    assert any(a["status"] == "DRY_RUN" for a in body["actions"])
    assert not iam.calls, "dry run must not touch IAM"
    assert sns.calls_to("publish")


def test_auto_suspend_executes_iam_calls_for_user(lambda_context, monkeypatch):
    monkeypatch.setenv("AUTO_SUSPEND", "true")
    event = {"mode": "suspicious", "suspicious": _suspicious(
        principal="arn:aws:iam::123456789012:user/admin-deploy",
    )}
    result, iam, *_ = _invoke(event, lambda_context)
    assert iam.calls_to("update_access_key")[0]["Status"] == "Inactive"
    assert iam.calls_to("put_user_policy")
    assert result["compliance_status"] == "PASS"


def test_non_privileged_anomaly_is_ticket_only(lambda_context):
    event = {"mode": "suspicious", "suspicious": _suspicious(
        principal="arn:aws:iam::123456789012:user/intern-readonly",
    )}
    result, iam, *_ = _invoke(event, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "PASS"
    assert body["actions"][0]["action"] == "ticket_only"
    assert not iam.calls


def test_readonly_admin_audit_not_privileged():
    """Regression: substring 'admin' matched admin-assistant/readonly-admin-audit."""
    assert handler_mod.is_privileged(["readonly-admin-audit"], []) is False
    assert handler_mod.is_privileged(["admin-assistant"], []) is False


def test_administratoraccess_role_privileged():
    assert handler_mod.is_privileged(["AdministratorAccess"], []) is True
    assert handler_mod.is_privileged(["break-glass-ops"], []) is True


def test_standing_privilege_review_fails_over_max(lambda_context):
    event = {"mode": "review", "roster": [
        {"principal": "a", "privileged": True, "privileged_standing_days": 30},
        {"principal": "b", "privileged": True, "privileged_standing_days": 0.5},
        {"principal": "c", "privileged": False, "privileged_standing_days": 400},
    ]}
    result, *_ = _invoke(event, lambda_context)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert len(body["detail"]["privilege_review"]["standing_privileged_violations"]) == 1


def test_bad_max_standing_env_is_config_error(lambda_context, monkeypatch):
    """Regression: float(os.environ...) raised uncaught ValueError per loop."""
    monkeypatch.setenv("MAX_STANDING_PRIV_DAYS", "abc")
    event = {"mode": "review", "roster": []}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_mode_without_payload_is_error(lambda_context):
    """Regression: event['lifecycle'] KeyError when mode passed explicitly."""
    result, *_ = _invoke({"mode": "lifecycle"}, lambda_context)
    assert result["compliance_status"] == "ERROR"


def test_simulation_is_stamped_and_guardduty_shaped(lambda_context):
    result, *_ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    # Simulation event has no `privileged` field — detection alone decides.
    assert body["suspension_required"] is True


def test_unknown_event_keys_ignored(lambda_context):
    """Regression: SuspiciousEvent(**raw) raised uncaught TypeError."""
    event = {"mode": "suspicious", "suspicious": _suspicious(evil="x")}
    result, *_ = _invoke(event, lambda_context)
    assert result["compliance_status"] in {"PASS", "FAIL"}  # evaluated, not crashed
