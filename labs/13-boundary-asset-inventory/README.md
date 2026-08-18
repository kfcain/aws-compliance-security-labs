# Authorization Boundary & Real-Time Asset Inventory

> Lab folder / original repo: `lab-boundary-asset-inventory`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Persistently generate authoritative inventories of in-boundary information resources, map federal data flows, and flag shadow resources outside the Minimum Assessment Scope.

**Primary risk:** Unknown or out-of-scope resources silently process federal data

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Inventory and boundary are prerequisites for every other control. You cannot monitor, encrypt, or delete what you do not know. |
| Compliance | FedRAMP KSI-PIY-GIV and Minimum Assessment Scope practice (KSI-AFR-MAS overlay); SCF AST-01/02/04, NET-03, CPL-01; NIST CM-8/CA-3; ISO asset management. |
| Financial / $$ | Scope gaps cause 3PAO findings, rework, and delayed ATO. Undiscovered stores expand breach blast radius and discovery cost. |
| Likelihood × Impact | High × Critical |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** Config Aggregator, Resource Explorer, Security Hub, Organizations, Lambda, EventBridge, DynamoDB, S3, Athena, Tag Editor
- **External:** SSP / MAS document

## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `AST-01`, `AST-02`, `AST-04`, `NET-03`, `CPL-01`, `GOV-01` |
| FedRAMP 20x KSI | `KSI-PIY-GIV`, `KSI-AFR-MAS`, `KSI-CNA-DFP`, `KSI-MLA-LET` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
13-boundary-asset-inventory/
  README.md
  RISK.md
  SPEC.md
  scf/lab-spec.json
  diagrams/architecture.tldr
  infrastructure/template.yaml
  src/handler.py
```

## Operator walkthrough

Configure the stack, collect evidence, and assemble the assessor package:
[WALKTHROUGH.md](./WALKTHROUGH.md). Shared steps:
[operator playbook](../../docs/walkthroughs/00-operator-playbook.md).

## Quick start

1. Work from `labs/13-boundary-asset-inventory/` in this monorepo (or use the original `lab-boundary-asset-inventory` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

> **Note:** the crosswalk tables embedded in `index.html` are a static
> 2026-08-01 snapshot for the walkthrough page. `scf/scf-mapping.generated.json`
> is the canonical crosswalk; regenerate the page from it rather than editing HTML.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
