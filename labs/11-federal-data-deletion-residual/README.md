# Federal Data Deletion & Residual-Data Proof (Class C)

> Lab folder / original repo: `lab-federal-data-deletion-residual`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Orchestrate agency-requested removal of federal customer data from live stores and backups, then persistently prove no residual copies remain (FedRAMP KSI-SVC-RUD / KSI-SVC-PRR).

**Primary risk:** Federal customer data remains after offboarding or spill cleanup

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Data lifecycle and sanitization are core confidentiality controls. Without residual-data proof, the program cannot close a federal data case. |
| Compliance | FedRAMP CR26 Class C KSI-SVC-RUD and KSI-SVC-PRR explicitly require prompt removal of unwanted federal customer data (including backups when appropriate) and persistent review after changes. Maps to SCF DCH-01/09, BCD-11, CRY-05; NIST SI-12/MP-6 themes; ISO disposal controls. |
| Financial / $$ | Failure to delete federal data drives contract breach, agency exit, breach-notification exposure, and ATO suspension risk. Manual hunt-and-delete burns high-cost engineering and GRC time. |
| Likelihood × Impact | Medium × Critical |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** S3, DynamoDB, RDS, AWS Backup, KMS, Step Functions, Lambda, EventBridge, Security Hub, SNS, Athena
- **External:** Agency deletion ticket / GRC case

## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `DCH-01`, `DCH-09`, `DCH-06`, `BCD-11`, `CRY-05`, `CLD-01` |
| FedRAMP 20x KSI | `KSI-SVC-RUD`, `KSI-SVC-PRR`, `KSI-SVC-SIN`, `KSI-AFR-PVL` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
11-federal-data-deletion-residual/
  README.md
  RISK.md
  SPEC.md
  scf/lab-spec.json
  diagrams/architecture.tldr
  infrastructure/template.yaml
  src/handler.py
```

## Quick start

1. Work from `labs/11-federal-data-deletion-residual/` in this monorepo (or use the original `lab-federal-data-deletion-residual` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
