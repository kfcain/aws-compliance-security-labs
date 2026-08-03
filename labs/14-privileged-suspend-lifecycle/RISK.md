# Risk Register Entry — Privileged Suspend & Account Lifecycle Automation

| Field | Value |
|-------|-------|
| Risk ID | RISK-14-01 |
| Lab | `14-privileged-suspend-lifecycle` |
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

**Orphaned or compromised privileged access to federal systems**

## Threat narrative

Orphaned admins, standing privileged roles, or delayed response to suspicious privileged activity enable federal data exfiltration.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1098 | Account Manipulation | Compromised or orphaned privileged accounts are re-provisioned or retained |
| T1078.004 | Valid Accounts: Cloud Accounts | Standing privileged access abused after credential theft |

## Security program impact

Privileged Access Management and automated lifecycle are mandatory for zero-trust. Suspend-on-suspicion closes the MFA gap after credential theft.

## Compliance impact

FedRAMP KSI-IAM-SUS, KSI-IAM-AAM, KSI-IAM-ELP/JIT/APM; SCF IAC-15/16/17/21; NIST AC/IA; PCI 7.x/8.x; ISO access control.

## Financial / business impact

Privileged misuse drives the highest-impact breaches. Automation cuts MTTC and reduces standing-privilege audit findings that block deals.

## Treatment & residual rationale

Detection-driven suspend (caller hints cannot de-escalate) with honest dry-run FAILs cuts privileged-abuse dwell time; a fast attacker inside the detection window remains High impact.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
