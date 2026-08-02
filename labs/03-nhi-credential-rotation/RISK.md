# Risk statement — Non-Human Identity Credential & Token Rotation

## Statement

**Long-lived machine credentials enabling lateral movement**

## Threat narrative

Stale IAM keys, CI tokens, and service principals enable silent privilege abuse.

## Security program impact

Non-human identities often outnumber humans 10:1+. Without inventory and rotation, secrets sprawl defeats IAM hygiene.

## Compliance impact

SCF IAC-15/21, FedRAMP KSI-SVC-SEC / KSI-IAM-JIT, NIST IA/AC, PCI DSS 8.6.x key management expectations, ISO crypto and access themes.

## Financial / business impact

Leaked CI/CD tokens cause multi-environment compromise. Rotation automation reduces emergency key-revocation fire drills and insurance questionnaire findings.

## Rating

| Factor | Value |
|--------|-------|
| Likelihood | High |
| Impact | High |
| Suggested treatment | Automate detection + evidence; escalate residual risk to GRC risk register |

## Residual risk if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
