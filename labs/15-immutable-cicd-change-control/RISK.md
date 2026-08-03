# Risk Register Entry — Immutable CI/CD Change Control & Deployment Validation

| Field | Value |
|-------|-------|
| Risk ID | RISK-15-01 |
| Lab | `15-immutable-cicd-change-control` |
| Owner (role) | DevSecOps Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | High / High |
| Residual likelihood / impact | Medium / Medium |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Untracked production changes bypass review and corrupt federal workloads**

## Threat narrative

Operators mutate production by console/SSH, bypassing review; unvalidated deploys introduce regressions that expose federal data.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Unvalidated deploys carry compromised artifacts to production |
| T1578 | Modify Cloud Compute Infrastructure | Console/SSH mutation bypasses the pipeline and its gates |

## Security program impact

Immutable infrastructure and automated deployment validation are the change-management control plane for cloud CSOs.

## Compliance impact

FedRAMP KSI-CMT-RMV, KSI-CMT-VTD, KSI-CMT-LMC, KSI-CMT-RVP, and significant-change notification practice; SCF CHG-01..04, CFG-01, TDA-06; NIST CM; ISO change management.

## Financial / business impact

Emergency changes without gates cause outages and audit failures. Redeploy-only models reduce mean-time-to-recover and assessor remediation cycles.

## Treatment & residual rationale

Exact pipeline-actor matching and gate/SHA validation close the bypasses; emergency-change misuse inside approved actors is the residual.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
