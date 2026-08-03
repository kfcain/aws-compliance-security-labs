# Risk Register Entry — Authorization Boundary & Real-Time Asset Inventory

| Field | Value |
|-------|-------|
| Risk ID | RISK-13-01 |
| Lab | `13-boundary-asset-inventory` |
| Owner (role) | GRC Engineering Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | High / Critical |
| Residual likelihood / impact | Medium / High |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Unknown or out-of-scope resources silently process federal data**

## Threat narrative

Shadow accounts, untagged data stores, or mis-scoped SaaS connectors process federal information outside the authorization boundary.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1526 | Cloud Service Discovery | Shadow resources outside the boundary are found by attackers first |
| T1538 | Cloud Service Dashboard | Unowned consoles/connectors process federal data unmonitored |

## Security program impact

Inventory and boundary are prerequisites for every other control. You cannot monitor, encrypt, or delete what you do not know.

## Compliance impact

FedRAMP KSI-PIY-GIV and Minimum Assessment Scope practice (KSI-AFR-MAS overlay); SCF AST-01/02/04, NET-03, CPL-01; NIST CM-8/CA-3; ISO asset management.

## Financial / business impact

Scope gaps cause 3PAO findings, rework, and delayed ATO. Undiscovered stores expand breach blast radius and discovery cost.

## Treatment & residual rationale

Boundary classification with no default in-scope accounts and fail-closed empty-inventory handling shrinks unknown-asset dwell; discovery lag remains the residual.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
