# Risk Register Entry — Persistent MFA Validation (Okta / Descope)

| Field | Value |
|-------|-------|
| Risk ID | RISK-01-01 |
| Lab | `01-mfa-continuous-validation` |
| Owner (role) | Identity Engineering Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | High / Critical |
| Residual likelihood / impact | Low / High |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Account takeover from missing or bypassed MFA**

## Threat narrative

Credential stuffing, phishing, and session hijacking against human accounts without enforced MFA.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | Adversary disables or downgrades MFA enrollment to keep access |
| T1621 | Multi-Factor Authentication Request Generation | MFA-fatigue push bombing against non-phishing-resistant factors |
| T1078.004 | Valid Accounts: Cloud Accounts | Stolen credentials used where MFA is missing or bypassed |

## Security program impact

Identity is the primary control plane. Gaps in MFA break zero-trust and privileged access programs.

## Compliance impact

Required by NIST 800-171 03.05.03, NIST 800-53 IA-2(1)/(2), PCI DSS 8.4.x, FedRAMP KSI-IAM-MFA, and ISO 27001 Annex A access controls via SCF IAC-06.

## Financial / business impact

Average account-takeover breach cost often exceeds $4M+ (industry reports). Failed FedRAMP/CMMC/PCI assessments block revenue and contracts. Manual MFA audits burn GRC hours every quarter.

## Treatment & residual rationale

Continuous factor-level validation with fail-closed evidence and same-day alerting turns silent MFA gaps into detected events; impact remains High because a successful takeover still reaches federal data.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
