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

- [ ] `sam build && sam deploy` provisions the stack; `cfn-lint` and `checkov` pass
- [ ] Handler returns `compliance_status` from real posture; unconfigured input yields `CONFIG_ERROR` (never `PASS`)
- [ ] A known-bad fixture drives `FAIL` with a Security Hub finding and SNS alert; a clean fixture drives `PASS`
- [ ] Evidence JSON is written to the KMS-encrypted evidence bucket with `data_source` stamped
- [ ] `pytest labs/14-privileged-suspend-lifecycle` passes (regression + behavior tests)
- [ ] Crosswalk, coverage, OSCAL, and assessment artifacts regenerate without drift

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

## Security requirements

- Least-privilege Lambda role scoped to named resources (no wildcard resources
  outside the justified allowlist); partition-agnostic ARNs (GovCloud-safe)
- Evidence bucket, SNS, SQS, logs, and Lambda env encrypted with the lab CMK
- No long-lived secrets in code or plaintext env vars — use Secrets Manager
- Fail closed: unconfigured or partial inputs return `CONFIG_ERROR`, never `PASS`;
  simulated data only via `{"mode": "simulation"}`, stamped in the evidence
- Destructive or account-modifying actions gated behind a stack parameter
  defaulting off (dry run)

## Threat model

Primary adversary objective and the technique this lab detects/mitigates are
enumerated with MITRE ATT&CK IDs in [RISK.md](./RISK.md). The control's
detection logic (`src/handler.py`) is the mitigation; the assessment
procedure in [ASSESSMENT.md](./ASSESSMENT.md) is how an assessor confirms it
operates. Primary technique: **T1098**.

Trust boundary: the worker runs with a least-privilege role in the account
under test, reads posture via AWS APIs (or the IdP API for lab 01), and writes
only to its own KMS-encrypted evidence bucket and SNS topic. Event input is
validated; caller-supplied fields never override a control decision.
