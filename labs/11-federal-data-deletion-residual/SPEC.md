# Specification — Federal Data Deletion & Residual-Data Proof (Class C)

## Why this lab exists (federal data first)

FedRAMP CR26 **Class C** KSIs `KSI-SVC-RUD` and `KSI-SVC-PRR` are explicit about **federal customer data**:

1. Unwanted federal customer data must be removed **promptly** when an agency requests it (offboarding, spill, change of use), **including from backups when appropriate**.
2. After changes, the provider must persistently review and remove **residual** elements that would harm confidentiality, integrity, or availability of federal customer data.

Underlying rules before automation:

- Know **which stores** hold federal data (tenant tags + inventory from lab 13).
- Encrypt those stores (lab 06) so residual copies are not plaintext sprawl.
- Delete is not “done” until a **residual scan returns zero hits**.
- Evidence must be machine-readable for persistent validation.

## Goal

Orchestrate deletion cases end-to-end and prove residual-free state.

## Actors

| Actor | Role |
|-------|------|
| Agency / GRC | Opens deletion case with tenant_id + reason |
| Deletion orchestrator (Step Functions) | Sequences live purge → backup purge → residual scan |
| Security Hub / SNS | Alerts on residual FAIL |
| Auditor | Consumes evidence package |

## Functional requirements

1. Accept a deletion case: `tenant_id`, `agency_id`, `reason ∈ {offboarding, spill, customer_request}`, `include_backups`.
2. Resolve a **catalog** of live stores and backup vaults tagged with `federal_tenant_id` (or configured tag).
3. Purge live data in S3 prefixes, DynamoDB partitions, and RDS tenant rows (service adapters).
4. Expire/delete in-scope AWS Backup recovery points when `include_backups` or spill policy requires it.
5. Run residual scan; **PASS only if hit count = 0** and backup path satisfied.
6. Emit evidence JSON with SCF + KSI IDs; open CRITICAL Security Hub finding on FAIL.

## Non-goals

- Legal hold / eDiscovery workflows (integrate separately; deletion must block if hold flag set — TODO hook).
- Cross-cloud SaaS subprocessors (track in lab 10; call their deletion APIs via adapters).

## Acceptance criteria

- [ ] `sam build && sam deploy` provisions the stack; `cfn-lint` and `checkov` pass
- [ ] Handler returns `compliance_status` from real posture; unconfigured input yields `CONFIG_ERROR` (never `PASS`)
- [ ] A known-bad fixture drives `FAIL` with a Security Hub finding and SNS alert; a clean fixture drives `PASS`
- [ ] Evidence JSON is written to the KMS-encrypted evidence bucket with `data_source` stamped
- [ ] `pytest labs/11-federal-data-deletion-residual` passes (regression + behavior tests)
- [ ] Crosswalk, coverage, OSCAL, and assessment artifacts regenerate without drift

## Threat model (abridged)

| Threat | Mitigation in lab |
|--------|-------------------|
| Operator marks delete complete without checking backups | `REQUIRE_BACKUP_PURGE` + backup actions in evidence |
| Tenant tag missing → incomplete catalog | FAIL/WARN when vault mapping empty; depend on lab 13 tags |
| Residual replicas (versioned S3, PITR) | Residual scan must include versions/PITR windows (extend adapters) |
| Premature delete under legal hold | Gate on `legal_hold=true` (extension point in case schema) |

## Evidence schema

See `src/handler.py` `build_evidence()`. Minimum fields: `case`, `catalog`, `live_purge_actions`, `backup_purge_actions`, `residual_hits`, `fedramp_20x_ksi`.

## Test vectors

```bash
# PASS path (demo)
python3 -c "from src.handler import handler; import json; print(handler({'case':{'tenant_id':'agency-a','reason':'offboarding'}}, None)['body'])"

# FAIL residual
python3 -c "from src.handler import handler; r=handler({'case':{'tenant_id':'agency-a','reason':'spill'},'simulate_residual_hits':[{'store':'s3','locator':'s3://bucket/agency-a/x','confidence':'high'}]}, None); print(r['body'])"
```

## Related labs

- **13** inventory/boundary supplies the catalog
- **12** backup vaults must support tenant-tagged recovery points
- **06** CMKs encrypt data at rest during residual windows

## Security requirements

- Least-privilege Lambda role scoped to named resources (no wildcard resources
  outside the justified allowlist); partition-agnostic ARNs (GovCloud-safe)
- Evidence bucket, SNS, SQS, logs, and Lambda env encrypted with the lab CMK
- No long-lived secrets in code or plaintext env vars — use Secrets Manager
- Fail closed: unconfigured or partial inputs return `CONFIG_ERROR`, never `PASS`;
  simulated data only via `{"mode": "simulation"}`, stamped in the evidence
- Destructive or account-modifying actions gated behind a stack parameter
  defaulting off (dry run)
