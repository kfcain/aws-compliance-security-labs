# Risk statement — KMS Encryption & Secrets Governance

## Statement

**Unencrypted data exposure and cryptographic non-conformance**

## Threat narrative

Data at rest or in transit lacks approved cryptography; keys are shared or never rotated.

## Security program impact

Cryptographic governance underpins confidentiality commitments and customer trust.

## Compliance impact

FedRAMP KSI-SVC-ENC/SNT; SCF CRY-01/03; NIST SC-13/SC-28; PCI DSS 3.x/4.x crypto; ISO 27001 crypto controls.

## Financial / business impact

Encryption failures trigger breach notification laws and contract liabilities. FIPS gaps block federal deals.

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
