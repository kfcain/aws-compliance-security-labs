# Risk Register Entry — Continuous Config Drift & Control Status

| Field | Value |
|-------|-------|
| Risk ID | RISK-04-01 |
| Lab | `04-config-drift-compliance` |
| Owner (role) | Cloud Compliance Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | Medium / High |
| Residual likelihood / impact | Low / Medium |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Silent configuration drift breaking baseline controls**

## Threat narrative

Resources drift from hardened baselines after change windows.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1578 | Modify Cloud Compute Infrastructure | Drifted resources diverge from the hardened baseline |
| T1562.007 | Impair Defenses: Disable or Modify Cloud Firewall | Security-relevant configuration quietly loosened post-deploy |

## Security program impact

Persistent evaluation replaces point-in-time audits and feeds Security Hub control status.

## Compliance impact

FedRAMP KSI-CNA-EIS and KSI-MLA-EVC; SCF CFG/CPL; NIST CM/CA; PCI DSS configuration standards; ISO configuration management.

## Financial / business impact

Drift causes repeat audit findings. Automated evidence reduces 3PAO/assessor billable hours and prevents production outages from insecure defaults.

## Treatment & residual rationale

Recorder-status checks plus per-rule compliance evaluation catch drift within a day; residual risk is drift inside the evaluation cadence.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
