# Specification — Terraform DR Readiness & State-Backend Resilience

## Goal

Evaluate a DR-readiness descriptor derived from Terraform to prove that a
disaster is recoverable: the Terraform state backend is resilient (so
recovery-by-reapply survives a region loss) and the declared architecture meets
the RTO/RPO the DR plan requires. Emit fail-closed, assessor-ready evidence.

## Non-goals

- Executing an actual failover or region evacuation (this validates that
  recovery is *possible*, not that it was *performed*)
- Runtime restore-drill outcomes and AWS Backup posture — that is lab 12
- Running `terraform` in the Lambda (the CI producer derives the descriptor)

## Functional requirements

1. Consume a DR descriptor from the event (`event.descriptor`) or the
   descriptor S3 bucket (`DESCRIPTOR_BUCKET`/`DESCRIPTOR_KEY`)
2. Evaluate **state-backend resilience**: remote+locking backend, state bucket
   versioning, KMS encryption, cross-region replication (local backend →
   critical)
3. Evaluate **DR architecture parity**: designated recovery region distinct
   from primary; each critical store cross-region durable (replication, or PITR
   + cross-region backup); failover routing (severity scales with RTO)
4. Compare declared RTO/RPO against `RTO_TARGET_MINUTES` / `RPO_TARGET_MINUTES`
5. Fail when any finding is at or above `FAIL_SEVERITY` (default `high`); emit
   evidence, a Security Hub ASFF finding, and an SNS alert
6. Emit the assessor-ready assurance case: provenance (`terraform_commit`,
   `collector_role`), a SHA-256 integrity manifest, and per-control mapping to
   the real NIST CP-family objectives with `SATISFIED` / `OTHER-THAN-SATISFIED`

## Acceptance criteria

- [ ] `sam build && sam deploy` provisions the stack; `cfn-lint` and `checkov` pass
- [ ] Handler returns `compliance_status` from a real descriptor; none supplied yields `CONFIG_ERROR`
- [ ] A local state backend yields a `critical` finding and `FAIL`; a resilient backend + cross-region-durable critical stores + failover routing yields `PASS`
- [ ] A critical store without cross-region durability is `critical`; declared RTO/RPO exceeding the targets fails
- [ ] Evidence carries provenance + a recomputable `evidence_manifest_sha256`, and the assurance case maps each control to its NIST objectives
- [ ] `pytest labs/17-terraform-dr-readiness` passes
- [ ] Crosswalk, coverage, OSCAL, and assessment artifacts regenerate without drift

## Descriptor schema (input)

```json
{
  "backend": {
    "backend_type": "s3", "bucket": "tf-state", "region": "us-east-1",
    "versioning": true, "kms_encrypted": true,
    "cross_region_replication": true, "locking": true, "lock_mechanism": "dynamodb"
  },
  "primary_region": "us-east-1",
  "recovery_region": "us-west-2",
  "data_stores": [
    {"address": "aws_dynamodb_table.sessions", "store_type": "aws_dynamodb_table",
     "critical": true, "cross_region_replication": true},
    {"address": "aws_s3_bucket.cui", "store_type": "aws_s3_bucket",
     "critical": true, "point_in_time_recovery": true, "cross_region_backup": true}
  ],
  "failover_routing": true,
  "declared_rto_minutes": 30,
  "declared_rpo_minutes": 15
}
```

## Configuration (env)

| Var | Meaning |
|-----|---------|
| `DESCRIPTOR_BUCKET` / `DESCRIPTOR_KEY` | Where CI drops the DR descriptor JSON |
| `FAIL_SEVERITY` | `critical\|high\|medium\|low` — fail threshold (default `high`) |
| `RTO_TARGET_MINUTES` / `RPO_TARGET_MINUTES` | DR-plan targets to compare against (0 = skip) |
| `TERRAFORM_COMMIT` / `TERRAFORM_WORKSPACE` | Provenance from the CI producer |

## Threat model

Primary technique and mitigation are enumerated with MITRE ATT&CK IDs in
[RISK.md](./RISK.md). Primary technique: **T1490 (Inhibit System Recovery)** —
an adversary (or a regional event) destroys the ability to recover; this lab
proves recovery is designed-in before it is needed.

Trust boundary: the worker reads only the DR descriptor from its descriptor
bucket (no cloud-mutation permissions, no terraform execution) and writes only
to its KMS-encrypted evidence bucket and SNS topic. The descriptor is validated;
malformed input yields `ERROR`, missing input yields `CONFIG_ERROR`.

## Security requirements

- Least-privilege Lambda role: read-only on the descriptor bucket, write-only on
  the evidence bucket; no Terraform/cloud-mutation permissions; partition-
  agnostic ARNs (GovCloud-safe)
- Descriptor and evidence buckets, SNS, SQS, logs, and Lambda env encrypted with
  the lab CMK; TLS-only and KMS-enforcing bucket policies
- No long-lived secrets in code or env
- Fail closed: no descriptor or bad config returns `CONFIG_ERROR`, never `PASS`;
  simulated data only via `{"mode": "simulation"}`, stamped in the evidence
