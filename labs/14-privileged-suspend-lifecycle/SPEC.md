# Specification — Privileged Suspend & Account Lifecycle Automation

## Why this lab exists (federal data first)

Phishing-resistant MFA (lab 01) reduces takeover risk. It does **not** stop:

- Orphaned privileged accounts after offboarding
- Standing admin roles that violate least privilege
- Active privileged sessions after GuardDuty detects abuse

CR26 requires:

| KSI | Outcome |
|-----|---------|
| `KSI-IAM-AAM` | Automate account/role/group lifecycle and privileges |
| `KSI-IAM-SUS` | Disable or secure privileged access on suspicious activity |
| `KSI-IAM-ELP` / `JIT` / `APM` | Least privilege, JIT elevation, passwordless/phishing-resistant where feasible |

Underlying rules:

1. Joiner/mover/leaver events from Okta/Descope drive Identity Center / IAM state — no ticket-only lag for leavers.
2. Privileged joiners require **JIT** + phishing-resistant MFA — not standing `AdministratorAccess`.
3. Suspicious privileged findings trigger **auto-suspend** (session revoke + permission set disable) with break-glass dual control.
4. Periodic review fails standing privilege beyond policy max days (default 1 day).

## Modes

| Mode | Input | Behavior |
|------|-------|----------|
| `lifecycle` | IdP JML event | Provision / reconcile / disable |
| `suspicious` | GuardDuty/CloudTrail anomaly | Suspend privileged principal |
| `review` | Privilege roster | Detect standing privilege |

## Acceptance criteria

- [ ] Leaver emits disable + session revoke + key disable actions
- [ ] Suspicious privileged demo path emits `SUSPENDED_PLACEHOLDER` actions when `AUTO_SUSPEND=true`
- [ ] Standing 30-day admin fails `review` mode
- [ ] Evidence lists control objectives for SUS/AAM/JIT

## Test vectors

```bash
cd labs/14-privileged-suspend-lifecycle
python3 -c "from src.handler import handler; import json; print(json.loads(handler({'mode':'review'}, None)['body'])['status'])"
python3 -c "from src.handler import handler; import json; print(json.loads(handler({'mode':'suspicious'}, None)['body'])['privileged_suspend_executed'])"
```

## Related labs

- Extends **01** MFA
- Consumes **05** GuardDuty findings
- Coordinates with **03** NHI for machine identities
