# Incident Response Automation Playbooks

> Lab folder / original repo: `lab-incident-response-automation`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Codify IR playbooks as Step Functions + Lambda: detect, contain, notify stakeholders, preserve evidence, and produce after-action artifacts.

**Primary risk:** Ad-hoc IR increases dwell time, cost, and regulatory penalties

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Repeatable IRP execution is required for maturity and FedRAMP INR KSIs. |
| Compliance | SCF IRO-01/02/04/10; FedRAMP KSI-INR-*; NIST IR; PCI DSS 12.10; ISO A.5.24–A.5.26. |
| Financial / $$ | Poor IR increases regulatory fines (e.g., breach notification delays) and recovery spend. Automation cuts overtime and consultant fees. |
| Likelihood × Impact | Medium × High |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** Security Hub, EventBridge, Step Functions, Lambda, SNS, SSM, S3, CloudWatch
- **External:** PagerDuty / Slack (optional)

## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `IRO-01`, `IRO-02`, `IRO-04`, `IRO-10`, `MON-02` |
| FedRAMP 20x KSI | `KSI-INR-IRP`, `KSI-INR-PRC`, `KSI-MLA-OSM` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
09-incident-response-automation/
  README.md
  RISK.md
  SPEC.md
  scf/lab-spec.json
  diagrams/architecture.tldr
  infrastructure/template.yaml
  src/handler.py
```

## Quick start

1. Work from `labs/09-incident-response-automation/` in this monorepo (or use the original `lab-incident-response-automation` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
