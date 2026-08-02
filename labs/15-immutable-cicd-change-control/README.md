# Immutable CI/CD Change Control & Deployment Validation

> Lab folder / original repo: `lab-immutable-cicd-change-control`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Enforce redeploy-from-version-control over in-place modification, automate deployment validation gates, and log all CSO changes for KSI-CMT-RMV / KSI-CMT-VTD / KSI-CMT-LMC.

**Primary risk:** Untracked production changes bypass review and corrupt federal workloads

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Immutable infrastructure and automated deployment validation are the change-management control plane for cloud CSOs. |
| Compliance | FedRAMP KSI-CMT-RMV, KSI-CMT-VTD, KSI-CMT-LMC, KSI-CMT-RVP, and significant-change notification practice; SCF CHG-01..04, CFG-01, TDA-06; NIST CM; ISO change management. |
| Financial / $$ | Emergency changes without gates cause outages and audit failures. Redeploy-only models reduce mean-time-to-recover and assessor remediation cycles. |
| Likelihood × Impact | High × High |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** CodePipeline, CodeBuild, CloudFormation / CDK, SCPs, CloudTrail, Config, EventBridge, Lambda, Security Hub, SNS, ECR
- **External:** GitHub / GitLab

## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `CHG-01`, `CHG-02`, `CHG-03`, `CHG-04`, `CFG-01`, `TDA-06` |
| FedRAMP 20x KSI | `KSI-CMT-RMV`, `KSI-CMT-VTD`, `KSI-CMT-LMC`, `KSI-CMT-RVP`, `KSI-AFR-SCN` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
15-immutable-cicd-change-control/
  README.md
  RISK.md
  SPEC.md
  scf/lab-spec.json
  diagrams/architecture.tldr
  infrastructure/template.yaml
  src/handler.py
```

## Quick start

1. Work from `labs/15-immutable-cicd-change-control/` in this monorepo (or use the original `lab-immutable-cicd-change-control` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
