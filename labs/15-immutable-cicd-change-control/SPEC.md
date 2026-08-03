# Specification — Immutable CI/CD Change Control & Deployment Validation

## Why this lab exists (federal data first)

Federal workloads must change through **reviewed, version-controlled redeploys**, not console mutation. Direct SG/IAM/CloudTrail changes create silent boundary and data-exposure risk.

CR26 Change Management:

| KSI | Outcome |
|-----|---------|
| `KSI-CMT-RMV` | Prefer redeploy of version-controlled resources over direct modify |
| `KSI-CMT-VTD` | Automate validation throughout deployment |
| `KSI-CMT-LMC` | Log and monitor CSO modifications |
| `KSI-CMT-RVP` | Persistently review change procedures |
| `KSI-AFR-SCN` | Classify significant changes (routine / adaptive / transformative) |

Underlying rules:

1. SCPs deny high-risk direct mutations for human principals in prod.
2. Pipeline is the only normal path to production; deploys reference immutable `commit_sha`.
3. Gates: IaC scan, policy-as-code, unit (+ integration) must pass; post-deploy validation required.
4. All change events logged; denylisted API calls by humans = FAIL.
5. SCN classification drives notification lead time.

## Functional requirements

1. Evaluate CloudTrail-like change events against forbidden direct-modify set.
2. Evaluate pipeline run gate matrix + post-deploy validation + commit binding.
3. Attach SCN classification metadata.
4. Emit procedure-review checklist evidence (`KSI-CMT-RVP`).

## Acceptance criteria

- [ ] `sam build && sam deploy` provisions the stack; `cfn-lint` and `checkov` pass
- [ ] Handler returns `compliance_status` from real posture; unconfigured input yields `CONFIG_ERROR` (never `PASS`)
- [ ] A known-bad fixture drives `FAIL` with a Security Hub finding and SNS alert; a clean fixture drives `PASS`
- [ ] Evidence JSON is written to the KMS-encrypted evidence bucket with `data_source` stamped
- [ ] `pytest labs/15-immutable-cicd-change-control` passes (regression + behavior tests)
- [ ] Crosswalk, coverage, OSCAL, and assessment artifacts regenerate without drift

## Test vectors

```bash
cd labs/15-immutable-cicd-change-control
python3 -c "from src.handler import handler; import json; print(json.loads(handler({}, None)['body'])['status'])"
python3 -c "from src.handler import handler; import json; r=handler({'pipeline_run':{'pipeline_name':'p','commit_sha':'x','gates':{'unit':True},'deployed':True,'post_deploy_validation':False,'change_class':'adaptive'}}, None); print(json.loads(r['body'])['status'])"
```

## Related labs

- **04** config intended state after deploy
- **07** CloudTrail is the change sensor
- **13** boundary resources must only change via this path

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
operates. Primary technique: **T1195.002**.

Trust boundary: the worker runs with a least-privilege role in the account
under test, reads posture via AWS APIs (or the IdP API for lab 01), and writes
only to its own KMS-encrypted evidence bucket and SNS topic. Event input is
validated; caller-supplied fields never override a control decision.
