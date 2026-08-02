# Backup Alignment & Recovery Testing (RTO/RPO)

> Lab folder / original repo: `lab-backup-recovery-rto-rpo`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Define RTO/RPO per critical federal workload, align AWS Backup plans and vault policy, run restore drills, and emit machine-readable evidence for KSI-RPL-* and KSI-CNA-OFA.

**Primary risk:** Unproven backups leave federal missions unrestorable after ransomware or outage

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Continuity is part of security. RPL KSIs require defined objectives, aligned backups, and tested recovery—not vault screenshots alone. |
| Compliance | FedRAMP KSI-RPL-RRO/ARP/ABO/TRC and KSI-CNA-OFA; SCF BCD-01/02/11/12; NIST CP family; ISO continuity; PCI backup requirements where card data exists. |
| Financial / $$ | Unplanned downtime and ransom payments dominate incident cost. Failed recovery tests delay FedRAMP authorization and raise cyber-insurance premiums. |
| Likelihood × Impact | Medium × Critical |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** AWS Backup, Backup Vault Lock, KMS, EC2, RDS, DynamoDB, EventBridge, Lambda, Step Functions, S3, CloudWatch


## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `BCD-01`, `BCD-02`, `BCD-11`, `BCD-12`, `CRY-05`, `AST-02` |
| FedRAMP 20x KSI | `KSI-RPL-RRO`, `KSI-RPL-ARP`, `KSI-RPL-ABO`, `KSI-RPL-TRC`, `KSI-CNA-OFA` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
12-backup-recovery-rto-rpo/
  README.md
  RISK.md
  SPEC.md
  scf/lab-spec.json
  diagrams/architecture.tldr
  infrastructure/template.yaml
  src/handler.py
```

## Quick start

1. Work from `labs/12-backup-recovery-rto-rpo/` in this monorepo (or use the original `lab-backup-recovery-rto-rpo` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
