# Immutable Audit Evidence Pipeline

> Lab folder / original repo: `lab-cloudtrail-evidence-pipeline`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Build an org-wide CloudTrail → S3 (Object Lock) → Athena/Security Lake pipeline that packages machine-readable evidence for FedRAMP 20x persistent validation.

**Primary risk:** Inability to prove who did what — audit failure and legal exposure

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Immutable telemetry is the backbone of continuous monitoring and accountability. |
| Compliance | FedRAMP persistent validation + KSI-MLA-OSM; SCF MON; NIST AU; PCI DSS 10.x; ISO logging. |
| Financial / $$ | Failed audits delay ATO. Weak logs increase legal discovery cost and weaken cyber-insurance claims. |
| Likelihood × Impact | Medium × High |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** CloudTrail, S3 Object Lock, EventBridge, Lambda, Athena, Security Lake, Glue


## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `MON-01`, `MON-02`, `CPL-02`, `CHG-01` |
| FedRAMP 20x KSI | `KSI-MLA-OSM`, `KSI-AFR-PVL`, `KSI-CMT-CHG` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
07-cloudtrail-evidence-pipeline/
  README.md
  RISK.md
  SPEC.md
  scf/lab-spec.json
  diagrams/architecture.tldr
  infrastructure/template.yaml
  src/handler.py
```

## Quick start

1. Work from `labs/07-cloudtrail-evidence-pipeline/` in this monorepo (or use the original `lab-cloudtrail-evidence-pipeline` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
