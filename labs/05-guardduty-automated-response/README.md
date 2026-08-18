# GuardDuty Threat Detection & Automated Response

> Lab folder / original repo: `lab-guardduty-automated-response`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Ingest VPC Flow Logs and CloudTrail into GuardDuty, centralize in Security Hub, and auto-contain via EventBridge → Lambda playbooks.

**Primary risk:** Delayed response to active compromise increases blast radius

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Detection without response is incomplete. Playbooks shrink mean time to contain (MTTC). |
| Compliance | SCF THR/MON/IRO; FedRAMP KSI-MLA-OSM and INR procedures; NIST DE/RS; PCI DSS logging and monitoring; ISO incident and monitoring controls. |
| Financial / $$ | Each hour of dwell time multiplies incident cost. Auto-containment limits ransomware blast radius and cyber-insurance deductibles. |
| Likelihood × Impact | Medium × Critical |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** VPC Flow Logs, CloudTrail, GuardDuty, Security Hub, EventBridge, Lambda, SNS, Step Functions


## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `THR-01`, `THR-03`, `MON-01`, `MON-02`, `IRO-02` |
| FedRAMP 20x KSI | `KSI-MLA-OSM`, `KSI-INR-PRC`, `KSI-CNA-MAT` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
05-guardduty-automated-response/
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

1. Work from `labs/05-guardduty-automated-response/` in this monorepo (or use the original `lab-guardduty-automated-response` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

> **Note:** the crosswalk tables embedded in `index.html` are a static
> 2026-08-01 snapshot for the walkthrough page. `scf/scf-mapping.generated.json`
> is the canonical crosswalk; regenerate the page from it rather than editing HTML.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
