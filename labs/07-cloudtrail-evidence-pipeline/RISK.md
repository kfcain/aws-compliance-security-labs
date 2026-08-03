# Risk Register Entry — Immutable Audit Evidence Pipeline

| Field | Value |
|-------|-------|
| Risk ID | RISK-07-01 |
| Lab | `07-cloudtrail-evidence-pipeline` |
| Owner (role) | Security Operations Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | Medium / High |
| Residual likelihood / impact | Low / Medium |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Inability to prove who did what — audit failure and legal exposure**

## Threat narrative

Missing, mutable, or incomplete logs prevent investigation and audit defense.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1562.008 | Impair Defenses: Disable or Modify Cloud Logs | StopLogging/DeleteTrail erases the record of the intrusion |
| T1070 | Indicator Removal | Mutable evidence buckets allow after-the-fact tampering |

## Security program impact

Immutable telemetry is the backbone of continuous monitoring and accountability.

## Compliance impact

FedRAMP persistent validation + KSI-MLA-OSM; SCF MON; NIST AU; PCI DSS 10.x; ISO logging.

## Financial / business impact

Failed audits delay ATO. Weak logs increase legal discovery cost and weaken cyber-insurance claims.

## Treatment & residual rationale

Trail status, log-file validation, and WORM bucket posture checks make log tampering detectable; residual risk concentrates in the response to an alert.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
