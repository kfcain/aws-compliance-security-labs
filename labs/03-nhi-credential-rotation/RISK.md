# Risk Register Entry — Non-Human Identity Credential & Token Rotation

| Field | Value |
|-------|-------|
| Risk ID | RISK-03-01 |
| Lab | `03-nhi-credential-rotation` |
| Owner (role) | Platform Security Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | High / High |
| Residual likelihood / impact | Medium / Medium |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Long-lived machine credentials enabling lateral movement**

## Threat narrative

Stale IAM keys, CI tokens, and service principals enable silent privilege abuse.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1552.001 | Unsecured Credentials: Credentials In Files | Long-lived keys and tokens leak via repos, images, and CI logs |
| T1078.004 | Valid Accounts: Cloud Accounts | Stale machine credentials reused for silent lateral movement |

## Security program impact

Non-human identities often outnumber humans 10:1+. Without inventory and rotation, secrets sprawl defeats IAM hygiene.

## Compliance impact

SCF IAC-15/21, FedRAMP KSI-SVC-SEC / KSI-IAM-JIT, NIST IA/AC, PCI DSS 8.6.x key management expectations, ISO crypto and access themes.

## Financial / business impact

Leaked CI/CD tokens cause multi-environment compromise. Rotation automation reduces emergency key-revocation fire drills and insurance questionnaire findings.

## Treatment & residual rationale

Live IAM/Secrets discovery with age thresholds converts credential sprawl into tracked findings; residual exposure is the rotation window itself.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
