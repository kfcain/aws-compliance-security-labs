# Continuous Config Drift & Control Status

> Lab folder / original repo: `lab-config-drift-compliance`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Use AWS Config + Security Hub to persistently evaluate resource posture against SCF-mapped rules and emit pass/fail evidence for auditors.

**Primary risk:** Silent configuration drift breaking baseline controls

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Persistent evaluation replaces point-in-time audits and feeds Security Hub control status. |
| Compliance | FedRAMP KSI-CNA-EIS and KSI-MLA-EVC; SCF CFG/CPL; NIST CM/CA; PCI DSS configuration standards; ISO configuration management. |
| Financial / $$ | Drift causes repeat audit findings. Automated evidence reduces 3PAO/assessor billable hours and prevents production outages from insecure defaults. |
| Likelihood × Impact | Medium × High |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** Config, Security Hub, EventBridge, Lambda, S3, SNS, Organizations


## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `CFG-01`, `CFG-02`, `CPL-01`, `CPL-02`, `MON-01` |
| FedRAMP 20x KSI | `KSI-CNA-EIS`, `KSI-MLA-EVC`, `KSI-AFR-PVL` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
04-config-drift-compliance/
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

1. Work from `labs/04-config-drift-compliance/` in this monorepo (or use the original `lab-config-drift-compliance` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

> **Note:** the crosswalk tables embedded in `index.html` are a static
> 2026-08-01 snapshot for the walkthrough page. `scf/scf-mapping.generated.json`
> is the canonical crosswalk; regenerate the page from it rather than editing HTML.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
