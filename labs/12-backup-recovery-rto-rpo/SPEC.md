# Specification — Backup Alignment & Recovery Testing (RTO/RPO)

## Why this lab exists (federal data first)

Confidentiality controls fail open under ransomware if you cannot **restore federal workloads** inside agreed time. CR26 Recovery Planning is an entire theme:

| KSI | Outcome |
|-----|---------|
| `KSI-RPL-RRO` | RTO/RPO defined and reviewed |
| `KSI-RPL-ARP` | Recovery plan aligns to those objectives |
| `KSI-RPL-ABO` | Backups align to RPO (frequency, retention, encryption) |
| `KSI-RPL-TRC` | Recovery capability is **tested** |
| `KSI-CNA-OFA` | Architecture optimized for availability / rapid recovery |

Underlying rules:

1. Every **mission-critical** federal asset has numeric RTO/RPO.
2. Backup frequency must be **≤ RPO**.
3. Vaults use **CMK + vault lock** (immutability against attacker deletion).
4. Restore drills run in an **isolated** account; measured duration must be **≤ RTO**.
5. Untested backups = non-compliant (not a documentation exercise).

## Goal

Persistently evaluate backup alignment and restore-test evidence for the critical asset register.

## Functional requirements

1. Ingest objectives per asset (RTO/RPO minutes, backup frequency, vault flags, last drill metrics).
2. Fail assets where frequency > RPO, vault lock/CMK missing (policy), or drill missing/failed/slow/stale.
3. Evaluate plan alignment for all mission_critical/high assets (`KSI-RPL-ARP`).
4. Emit evidence with drill procedure steps and KSI IDs.

## Acceptance criteria

- [ ] `sam build && sam deploy` provisions the stack; `cfn-lint` and `checkov` pass
- [ ] Handler returns `compliance_status` from real posture; unconfigured input yields `CONFIG_ERROR` (never `PASS`)
- [ ] A known-bad fixture drives `FAIL` with a Security Hub finding and SNS alert; a clean fixture drives `PASS`
- [ ] Evidence JSON is written to the KMS-encrypted evidence bucket with `data_source` stamped
- [ ] `pytest labs/12-backup-recovery-rto-rpo` passes (regression + behavior tests)
- [ ] Crosswalk, coverage, OSCAL, and assessment artifacts regenerate without drift

## Test vectors

```bash
cd labs/12-backup-recovery-rto-rpo
python3 -c "from src.handler import handler; import json; print(json.loads(handler({}, None)['body'])['status'])"
```

## Related labs

- **11** needs tenant-aware backup purge without breaking RPO for *other* tenants
- **08** isolated restore VPC / segmentation
- **07** evidence immutability for drill artifacts

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
operates. Primary technique: **T1490**.

Trust boundary: the worker runs with a least-privilege role in the account
under test, reads posture via AWS APIs (or the IdP API for lab 01), and writes
only to its own KMS-encrypted evidence bucket and SNS topic. Event input is
validated; caller-supplied fields never override a control decision.
