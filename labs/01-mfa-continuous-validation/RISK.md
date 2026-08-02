# Risk statement — Persistent MFA Validation (Okta / Descope)

## Statement

**Account takeover from missing or bypassed MFA**

## Threat narrative

Credential stuffing, phishing, and session hijacking against human accounts without enforced MFA.

## Security program impact

Identity is the primary control plane. Gaps in MFA break zero-trust and privileged access programs.

## Compliance impact

Required by NIST 800-171 03.05.03, NIST 800-53 IA-2(1)/(2), PCI DSS 8.4.x, FedRAMP KSI-IAM-MFA, and ISO 27001 Annex A access controls via SCF IAC-06.

## Financial / business impact

Average account-takeover breach cost often exceeds $4M+ (industry reports). Failed FedRAMP/CMMC/PCI assessments block revenue and contracts. Manual MFA audits burn GRC hours every quarter.

## Rating

| Factor | Value |
|--------|-------|
| Likelihood | High |
| Impact | Critical |
| Suggested treatment | Automate detection + evidence; escalate residual risk to GRC risk register |

## Residual risk if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
