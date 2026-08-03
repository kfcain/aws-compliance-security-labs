# Risk Register Entry — GuardDuty Threat Detection & Automated Response

| Field | Value |
|-------|-------|
| Risk ID | RISK-05-01 |
| Lab | `05-guardduty-automated-response` |
| Owner (role) | SOC Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | Medium / Critical |
| Residual likelihood / impact | Medium / High |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Delayed response to active compromise increases blast radius**

## Threat narrative

Active compromise (crypto mining, credential exfil, C2) goes unnoticed or uncontained.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1562.001 | Impair Defenses: Disable or Modify Tools | Adversary disables detection before acting on objectives |
| T1046 | Network Service Discovery | Reconnaissance and brute force that GuardDuty findings surface |

## Security program impact

Detection without response is incomplete. Playbooks shrink mean time to contain (MTTC).

## Compliance impact

SCF THR/MON/IRO; FedRAMP KSI-MLA-OSM and INR procedures; NIST DE/RS; PCI DSS logging and monitoring; ISO incident and monitoring controls.

## Financial / business impact

Each hour of dwell time multiplies incident cost. Auto-containment limits ransomware blast radius and cyber-insurance deductibles.

## Treatment & residual rationale

Detector-posture validation and severity-gated sweeps shrink dwell time; compromise likelihood is unchanged but blast radius and MTTC drop.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
