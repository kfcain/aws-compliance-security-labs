# Risk Register Entry — Incident Response Automation Playbooks

| Field | Value |
|-------|-------|
| Risk ID | RISK-09-01 |
| Lab | `09-incident-response-automation` |
| Owner (role) | IR Program Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | Medium / High |
| Residual likelihood / impact | Medium / Medium |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Ad-hoc IR increases dwell time, cost, and regulatory penalties**

## Threat narrative

Manual IR playbooks fail under stress; stakeholders are notified late; evidence is incomplete.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1486 | Data Encrypted for Impact | Ransomware where slow, manual IR maximizes encrypted footprint |
| T1490 | Inhibit System Recovery | Adversary deletes recovery paths while responders improvise |

## Security program impact

Repeatable IRP execution is required for maturity and FedRAMP INR KSIs.

## Compliance impact

SCF IRO-01/02/04/10; FedRAMP KSI-INR-*; NIST IR; PCI DSS 12.10; ISO A.5.24–A.5.26.

## Financial / business impact

Poor IR increases regulatory fines (e.g., breach notification delays) and recovery spend. Automation cuts overtime and consultant fees.

## Treatment & residual rationale

Runbook presence/state and confirmed-subscriber checks keep the IR machinery provably ready; incident frequency is unchanged but execution risk drops.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
