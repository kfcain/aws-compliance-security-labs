# Risk Register Entry — KMS Encryption & Secrets Governance

| Field | Value |
|-------|-------|
| Risk ID | RISK-06-01 |
| Lab | `06-kms-encryption-governance` |
| Owner (role) | Key Management Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | Medium / Critical |
| Residual likelihood / impact | Low / High |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Unencrypted data exposure and cryptographic non-conformance**

## Threat narrative

Data at rest or in transit lacks approved cryptography; keys are shared or never rotated.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1552 | Unsecured Credentials | Secrets without rotation or key governance leak and persist |
| T1486 | Data Encrypted for Impact | Weak key governance amplifies ransomware and extortion impact |

## Security program impact

Cryptographic governance underpins confidentiality commitments and customer trust.

## Compliance impact

FedRAMP KSI-SVC-ENC/SNT; SCF CRY-01/03; NIST SC-13/SC-28; PCI DSS 3.x/4.x crypto; ISO 27001 crypto controls.

## Financial / business impact

Encryption failures trigger breach notification laws and contract liabilities. FIPS gaps block federal deals.

## Treatment & residual rationale

Rotation and public-key-policy sweeps plus secret-age governance close the most common crypto failures; impact stays High because a key compromise is still severe.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
