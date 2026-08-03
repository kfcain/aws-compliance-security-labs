# Risk Register Entry — Backup Alignment & Recovery Testing (RTO/RPO)

| Field | Value |
|-------|-------|
| Risk ID | RISK-12-01 |
| Lab | `12-backup-recovery-rto-rpo` |
| Owner (role) | Resilience Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | Medium / Critical |
| Residual likelihood / impact | Low / High |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Unproven backups leave federal missions unrestorable after ransomware or outage**

## Threat narrative

Backups exist on paper but are unencrypted, misaligned to RPO, or never restore-tested—so ransomware or region loss destroys federal mission availability.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1490 | Inhibit System Recovery | Ransomware targets backups first; untested restores fail when needed |
| T1486 | Data Encrypted for Impact | Recovery objectives unmet turns encryption events into mission loss |

## Security program impact

Continuity is part of security. RPL KSIs require defined objectives, aligned backups, and tested recovery—not vault screenshots alone.

## Compliance impact

FedRAMP KSI-RPL-RRO/ARP/ABO/TRC and KSI-CNA-OFA; SCF BCD-01/02/11/12; NIST CP family; ISO continuity; PCI backup requirements where card data exists.

## Financial / business impact

Unplanned downtime and ransom payments dominate incident cost. Failed recovery tests delay FedRAMP authorization and raise cyber-insurance premiums.

## Treatment & residual rationale

Objective-vs-drill evaluation with strict result coercion surfaces unproven backups before they are needed; a regional event still carries High impact.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
