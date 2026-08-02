# VPC Network Segmentation & Flow Visibility

> Lab folder / original repo: `lab-vpc-network-segmentation`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Implement least-privilege network paths with Security Groups, NACLs, Network Firewall, and Flow Log analytics aligned to PCI DSS and FedRAMP CNA KSIs.

**Primary risk:** Flat networks enable lateral movement and PCI scope expansion

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Segmentation reduces blast radius and clarifies trust boundaries. |
| Compliance | FedRAMP KSI-CNA-RNT/MAT; SCF NET; NIST SC/AC; PCI DSS network segmentation; ISO network controls. |
| Financial / $$ | PCI scope expansion multiplies assessment cost. Network breaches amplify ransomware payouts and downtime. |
| Likelihood × Impact | Medium × High |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** VPC, Security Groups, Network Firewall, VPC Flow Logs, Config, GuardDuty, Lambda


## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `NET-01`, `NET-04`, `AST-04`, `CLD-06` |
| FedRAMP 20x KSI | `KSI-CNA-RNT`, `KSI-CNA-MAT`, `KSI-SVC-SNT` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
08-vpc-network-segmentation/
  README.md
  RISK.md
  SPEC.md
  scf/lab-spec.json
  diagrams/architecture.tldr
  infrastructure/template.yaml
  src/handler.py
```

## Quick start

1. Work from `labs/08-vpc-network-segmentation/` in this monorepo (or use the original `lab-vpc-network-segmentation` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
