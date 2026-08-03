# Specification — Terraform State Drift Detection & Remediation Governance

## Goal

Detect out-of-band drift in Terraform-managed infrastructure by evaluating a
machine-readable Terraform plan, classify each drifted resource by severity,
apply an ignore list for expected drift, and emit fail-closed compliance
evidence with Security Hub findings and SNS alerts.

## Non-goals

- Running `terraform plan`/`apply` inside the Lambda (needs the binary + cloud
  credentials — that is the CI producer's job)
- Auto-remediation (a gated CI apply with approval owns that — tfdrift's safety
  model; this lab reports and alerts)
- Full enterprise GRC platform replacement

## Functional requirements

1. Consume a `terraform show -json` plan document from the event (`event.plan`)
   or the plan-artifact S3 bucket (`PLAN_BUCKET`/`PLAN_KEY`)
2. Prefer the dedicated top-level `resource_drift` array; fall back to non-no-op
   `resource_changes`
3. Classify each drifted resource by severity (critical/high/medium/low) from
   resource type + attribute + action, tfdrift-style
4. Honor `DRIFT_IGNORE` glob patterns (`.tfdriftignore`-style) as expected drift
5. Fail when any drift is at or above `FAIL_SEVERITY` (default `high`); emit
   evidence JSON, a Security Hub ASFF finding, and an SNS alert on failure
6. Emit an assessor-ready assurance case: provenance (`terraform_commit`,
   `collector_role`, workspace), a SHA-256 integrity manifest over the package,
   and per-control objective mapping (NIST 800-171 r3 + 800-53 r5 + ODP ids)
   with a `SATISFIED` / `OTHER-THAN-SATISFIED` status

## Acceptance criteria

- [ ] `sam build && sam deploy` provisions the stack; `cfn-lint` and `checkov` pass
- [ ] Handler returns `compliance_status` from a real plan; no plan supplied yields `CONFIG_ERROR` (never `PASS`)
- [ ] A plan with a security-group ingress drift yields `FAIL` (critical) with a Security Hub finding and SNS alert; a tags-only drift is `low` and passes at the default threshold
- [ ] An ignored resource (`DRIFT_IGNORE`) is reported under `ignored_drift`, not `FAIL`
- [ ] Evidence JSON is written to the KMS-encrypted evidence bucket with `data_source` stamped
- [ ] Evidence carries a provenance block (`terraform_commit`, `collector_role`) and a recomputable `evidence_manifest_sha256`
- [ ] The assurance case maps each control to its NIST 800-171 r3 / 800-53 r5 objectives with `SATISFIED` / `OTHER-THAN-SATISFIED` status
- [ ] `pytest labs/16-terraform-drift-detection` passes
- [ ] Crosswalk, coverage, OSCAL, and assessment artifacts regenerate without drift

## Evidence schema (minimum)

```json
{
  "lab_id": "16-terraform-drift-detection",
  "checked_at": "ISO-8601",
  "status": "PASS|FAIL|ERROR|CONFIG_ERROR|NOT_APPLICABLE",
  "data_source": "event|s3|simulation",
  "drifted_resource_count": 0,
  "drift_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
  "actionable_drift": [],
  "ignored_drift": [],
  "scf_controls": ["CFG-01","CFG-02","CPL-01","MON-01","CHG-02"],
  "fedramp_20x_ksi": ["KSI-AFR-PVL","KSI-CNA-EIS","KSI-CMT-RMV","KSI-MLA-EVC"],
  "provenance": {
    "collected_at": "ISO-8601",
    "collector_role": "arn:...:role/grc-evidence-reader",
    "terraform_commit": "abc123",
    "terraform_workspace": "prod",
    "evidence_manifest_sha256": "…64 hex…"
  },
  "assurance_case": [
    {
      "scf_control": "CFG-02",
      "status": "SATISFIED",
      "nist_800_171_r3_objectives": ["03.04.01.a","03.04.02.a"],
      "nist_800_53_r5_objectives": ["CM-02","CM-06"],
      "odp_references": ["A.03.04.02.ODP[01]"]
    }
  ]
}
```

The `terraform_commit`/`terraform_workspace` come from the CI producer (event
fields or `TERRAFORM_COMMIT`/`TERRAFORM_WORKSPACE` env); absent, they are
honestly recorded as `unknown`/`default`. See `governance/` for the ODP
register, the read-only evidence collector, and the OPA/Conftest gate.

## Configuration (env)

| Var | Meaning |
|-----|---------|
| `PLAN_BUCKET` / `PLAN_KEY` | Where CI drops `terraform show -json` output |
| `FAIL_SEVERITY` | `critical\|high\|medium\|low` — fail threshold (default `high`) |
| `DRIFT_IGNORE` | Comma-separated glob patterns for expected drift |
| `REMEDIATION_MODE` | `report\|dry_run` — remediation posture recorded in evidence |

## Threat model

Primary technique and mitigation are enumerated with MITRE ATT&CK IDs in
[RISK.md](./RISK.md). Primary technique: **T1578 (Modify Cloud Compute
Infrastructure)** — an actor mutates managed infrastructure out of band; this
lab surfaces the divergence as severity-classified, alertable evidence.

Trust boundary: the worker reads only plan JSON from its plan-artifact bucket
(no cloud-mutation permissions, no terraform execution) and writes only to its
KMS-encrypted evidence bucket and SNS topic. The plan document is validated;
malformed entries yield `ERROR`, and a missing plan yields `CONFIG_ERROR`.

## Security requirements

- Least-privilege Lambda role: read-only on the plan-artifact bucket, write-only
  on the evidence bucket; no Terraform/cloud-mutation permissions; partition-
  agnostic ARNs (GovCloud-safe)
- Plan-artifact and evidence buckets, SNS, SQS, logs, and Lambda env encrypted
  with the lab CMK; TLS-only and KMS-enforcing bucket policies
- No long-lived secrets in code or env
- Fail closed: no plan or bad config returns `CONFIG_ERROR`, never `PASS`;
  simulated data only via `{"mode": "simulation"}`, stamped in the evidence
- Remediation (auto-apply) is never performed by the function; it is a gated CI
  concern (`REMEDIATION_MODE` records intent only)
