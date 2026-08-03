# Risk Register Entry — Terraform DR Readiness & State-Backend Resilience

| Field | Value |
|-------|-------|
| Risk ID | RISK-17-01 |
| Lab | `17-terraform-dr-readiness` |
| Owner (role) | Resilience Engineering Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | Medium / Critical |
| Residual likelihood / impact | Low / High |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**A disaster is unrecoverable because the Terraform state backend or the declared architecture is not DR-ready**

## Threat narrative

Recovery of a Terraform-managed system depends on two things being true before
the disaster: the state backend survives (so `terraform apply` can rebuild),
and the code encodes a recoverable architecture (recovery region, cross-region
durable data, failover routing). In practice the state backend is often a local
file or an un-replicated bucket, and "DR" is a paragraph in a runbook rather
than declared infrastructure. When a region is lost — or an adversary
deliberately destroys backups and recovery paths — the team discovers the gap
at the worst possible moment.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1490 | Inhibit System Recovery | Deleting backups / recovery paths is a top ransomware move; unproven DR is the exposure |
| T1485 | Data Destruction | Destruction of a non-replicated data store or state backend is unrecoverable |
| T1486 | Data Encrypted for Impact | Ransomware whose blast radius is set by whether cross-region recovery exists |

## Security program impact

Continuity is part of security. Recovery objectives (RPL KSIs) require aligned
backups and a tested, recoverable plan — not vault screenshots. This lab moves
DR from documentation to a measurable property of the IaC.

## Compliance impact

FedRAMP 20x KSI-RPL-RRO/ARP/ABO (align recovery objectives, plan, and backups),
KSI-CNA-OFA (optimize for availability and rapid recovery), and KSI-CNA-EIS
(the state backend enforces the intended DR baseline); SCF BCD-01/02/11/12,
CFG-01; NIST 800-53 CP family (CP-01/02/09/10) and CM-01/09; ISO 27001
continuity controls; PCI backup requirements where card data exists.

## Financial / business impact

Unplanned downtime and ransom payments dominate incident cost, and a failed
recovery delays or forfeits authorization. Proving DR readiness from IaC catches
the "our state was in one region" and "the DR bucket had no replication" classes
of failure before an incident, not during one.

## Treatment & residual rationale

Continuous evaluation of the state backend's resilience and the declared DR
architecture against RTO/RPO targets, with fail-closed handling and an
integrity-sealed assurance case, converts an untested assumption into tracked,
alertable evidence. Residual risk is the gap between "recovery is designed-in"
(what this lab proves) and "recovery was executed within objective" (a live
failover exercise — see lab 12 for tested restore evidence).

## Consequences if untreated

- Unrecoverable region loss or backup-destruction event; mission outage
- Delayed or forfeited ATO from unproven contingency controls
- Higher cyber-insurance premiums and possible coverage exclusions
