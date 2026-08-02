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

- [ ] Demo set includes one PASS mission-critical and one FAIL legacy asset
- [ ] Stale restore test (>90d) fails mission_critical
- [ ] Evidence lists `drill_procedure` suitable for runbooks
- [ ] SCF mapping generated

## Test vectors

```bash
cd labs/12-backup-recovery-rto-rpo
python3 -c "from src.handler import handler; import json; print(json.loads(handler({}, None)['body'])['status'])"
```

## Related labs

- **11** needs tenant-aware backup purge without breaking RPO for *other* tenants
- **08** isolated restore VPC / segmentation
- **07** evidence immutability for drill artifacts
