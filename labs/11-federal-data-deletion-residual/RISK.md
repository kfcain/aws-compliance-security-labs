# Risk Register Entry — Federal Data Deletion & Residual-Data Proof (Class C)

| Field | Value |
|-------|-------|
| Risk ID | RISK-11-01 |
| Lab | `11-federal-data-deletion-residual` |
| Owner (role) | Data Governance Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | Medium / Critical |
| Residual likelihood / impact | Low / High |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Federal customer data remains after offboarding or spill cleanup**

## Threat narrative

Agency offboarding or spill-cleanup leaves federal customer data in live stores, snapshots, replicas, or backups.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1530 | Data from Cloud Storage | Residual federal data in stores, versions, and backups remains stealable after "deletion" |

## Security program impact

Data lifecycle and sanitization are core confidentiality controls. Without residual-data proof, the program cannot close a federal data case.

## Compliance impact

FedRAMP CR26 Class C KSI-SVC-RUD and KSI-SVC-PRR explicitly require prompt removal of unwanted federal customer data (including backups when appropriate) and persistent review after changes. Maps to SCF DCH-01/09, BCD-11, CRY-05; NIST SI-12/MP-6 themes; ISO disposal controls.

## Financial / business impact

Failure to delete federal data drives contract breach, agency exit, breach-notification exposure, and ATO suspension risk. Manual hunt-and-delete burns high-cost engineering and GRC time.

## Treatment & residual rationale

Real residual scans across versions, tables, and recovery points with fail-closed verdicts make incomplete deletion visible; impact stays High given the federal-data stakes.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
