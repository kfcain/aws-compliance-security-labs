# Risk statement — Authorization Boundary & Real-Time Asset Inventory

## Statement

**Unknown or out-of-scope resources silently process federal data**

## Threat narrative

Shadow accounts, untagged data stores, or mis-scoped SaaS connectors process federal information outside the authorization boundary.

## Security program impact

Inventory and boundary are prerequisites for every other control. You cannot monitor, encrypt, or delete what you do not know.

## Compliance impact

FedRAMP KSI-PIY-GIV and Minimum Assessment Scope practice (KSI-AFR-MAS overlay); SCF AST-01/02/04, NET-03, CPL-01; NIST CM-8/CA-3; ISO asset management.

## Financial / business impact

Scope gaps cause 3PAO findings, rework, and delayed ATO. Undiscovered stores expand breach blast radius and discovery cost.

## Rating

| Factor | Value |
|--------|-------|
| Likelihood | High |
| Impact | Critical |
| Suggested treatment | Automate detection + evidence; escalate residual risk to GRC risk register |

## Residual risk if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
