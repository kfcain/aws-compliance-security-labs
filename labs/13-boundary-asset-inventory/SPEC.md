# Specification — Authorization Boundary & Real-Time Asset Inventory

## Why this lab exists (federal data first)

You cannot encrypt, monitor, delete, or recover federal data that is **outside the known authorization boundary**. FedRAMP Minimum Assessment Scope practice and CR26 `KSI-PIY-GIV` require authoritative, automatable inventories.

Underlying rules:

1. Publish a **MAS / boundary definition**: in-scope accounts, services, inherited providers, data-flow summary.
2. Continuously discover resources (Config Aggregator / Resource Explorer).
3. Classify: `in_boundary` | `inherited` | `out_of_boundary` | `unknown`.
4. Any resource that `processes_federal_data` and is `out_of_boundary` is **CRITICAL**.
5. Federal data resources must carry required tags (`federal_tenant_id`, `data_classification`, `boundary_status`, `owner`).
6. Maintain a companion **logging event-type inventory** (`KSI-MLA-LET`).

## Goal

Persistently prove inventory completeness and boundary hygiene.

## Functional requirements

1. Load boundary definition (versioned MAS).
2. Normalize inventory items from Config/Explorer (lab accepts JSON inventory).
3. Classify + collect shadow/federal-shadow sets.
4. Emit FAIL if any classification issues; attach event-type inventory.

## Acceptance criteria

- [ ] `sam build && sam deploy` provisions the stack; `cfn-lint` and `checkov` pass
- [ ] Handler returns `compliance_status` from real posture; unconfigured input yields `CONFIG_ERROR` (never `PASS`)
- [ ] A known-bad fixture drives `FAIL` with a Security Hub finding and SNS alert; a clean fixture drives `PASS`
- [ ] Evidence JSON is written to the KMS-encrypted evidence bucket with `data_source` stamped
- [ ] `pytest labs/13-boundary-asset-inventory` passes (regression + behavior tests)
- [ ] Crosswalk, coverage, OSCAL, and assessment artifacts regenerate without drift

## Test vectors

```bash
cd labs/13-boundary-asset-inventory
python3 -c "from src.handler import handler; import json; b=json.loads(handler({}, None)['body']); print(b['status'], len(b['federal_data_outside_boundary']))"
```

## Related labs

- Feeds **11** deletion catalog
- Feeds **04** config scope
- Feeds **07** which accounts must have org trails

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
operates. Primary technique: **T1526**.

Trust boundary: the worker runs with a least-privilege role in the account
under test, reads posture via AWS APIs (or the IdP API for lab 01), and writes
only to its own KMS-encrypted evidence bucket and SNS topic. Event input is
validated; caller-supplied fields never override a control decision.
