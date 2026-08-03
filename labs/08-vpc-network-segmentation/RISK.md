# Risk Register Entry — VPC Network Segmentation & Flow Visibility

| Field | Value |
|-------|-------|
| Risk ID | RISK-08-01 |
| Lab | `08-vpc-network-segmentation` |
| Owner (role) | Network Security Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | Medium / High |
| Residual likelihood / impact | Low / Medium |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Flat networks enable lateral movement and PCI scope expansion**

## Threat narrative

Overly permissive Security Groups and flat VPCs enable lateral movement and expand PCI CDE scope.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1021 | Remote Services | World-open SSH/RDP is the classic lateral-movement doorway |
| T1046 | Network Service Discovery | Flat networks let scanning enumerate everything reachable |

## Security program impact

Segmentation reduces blast radius and clarifies trust boundaries.

## Compliance impact

FedRAMP KSI-CNA-RNT/MAT; SCF NET; NIST SC/AC; PCI DSS network segmentation; ISO network controls.

## Financial / business impact

PCI scope expansion multiplies assessment cost. Network breaches amplify ransomware payouts and downtime.

## Treatment & residual rationale

Flow-log coverage and world-open sensitive-port sweeps eliminate the silent flat-network state; residual exposure is approved-but-risky ingress.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
