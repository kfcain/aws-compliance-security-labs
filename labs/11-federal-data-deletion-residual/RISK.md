# Risk statement — Federal Data Deletion & Residual-Data Proof (Class C)

## Statement

**Federal customer data remains after offboarding or spill cleanup**

## Threat narrative

Agency offboarding or spill-cleanup leaves federal customer data in live stores, snapshots, replicas, or backups.

## Security program impact

Data lifecycle and sanitization are core confidentiality controls. Without residual-data proof, the program cannot close a federal data case.

## Compliance impact

FedRAMP CR26 Class C KSI-SVC-RUD and KSI-SVC-PRR explicitly require prompt removal of unwanted federal customer data (including backups when appropriate) and persistent review after changes. Maps to SCF DCH-01/09, BCD-11, CRY-05; NIST SI-12/MP-6 themes; ISO disposal controls.

## Financial / business impact

Failure to delete federal data drives contract breach, agency exit, breach-notification exposure, and ATO suspension risk. Manual hunt-and-delete burns high-cost engineering and GRC time.

## Rating

| Factor | Value |
|--------|-------|
| Likelihood | Medium |
| Impact | Critical |
| Suggested treatment | Automate detection + evidence; escalate residual risk to GRC risk register |

## Residual risk if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
