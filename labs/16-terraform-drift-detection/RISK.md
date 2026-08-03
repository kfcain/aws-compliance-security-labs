# Risk Register Entry — Terraform State Drift Detection & Remediation Governance

| Field | Value |
|-------|-------|
| Risk ID | RISK-16-01 |
| Lab | `16-terraform-drift-detection` |
| Owner (role) | Platform Engineering Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | High / High |
| Residual likelihood / impact | Medium / Medium |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Out-of-band changes drift Terraform-managed infrastructure away from its declared baseline and evade change control**

## Threat narrative

Console edits, break-glass scripts, and other tooling mutate cloud resources
that Terraform is supposed to own. The declared state and reality diverge:
security groups are widened, IAM policies are loosened, or resources are
deleted — none of it reviewed. Undetected, the drift either persists as an
unmanaged risk or is silently reverted by the next `apply`, masking a real
change. Sophisticated actors exploit exactly this gap to make changes that
never appear in a pull request.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1578 | Modify Cloud Compute Infrastructure | Out-of-band mutation of managed resources is the drift itself |
| T1562.007 | Impair Defenses: Disable or Modify Cloud Firewall | Widened security groups are the highest-severity drift class |
| T1098 | Account Manipulation | Loosened IAM policies/roles drift outside review |

## Security program impact

Infrastructure-as-Code is only a control if the declared state is the state.
Drift detection closes the loop between the pipeline (lab 15) and reality,
proving the baseline holds between deploys.

## Compliance impact

FedRAMP 20x KSI-CNA-EIS (enforce intended state) and KSI-CMT-RMV (redeploy
from version control rather than direct modification); SCF CFG-01/02, CPL-01,
MON-01, CHG-02; NIST 800-53 CM-2/CM-3/CM-6; PCI DSS change-control and
configuration standards; ISO 27001 configuration and change management.

## Financial / business impact

Undetected drift causes outages when a later apply reverts an emergency fix,
and it hides unauthorized changes that become audit findings and breach
vectors. Automated drift evidence cuts assessor prep time and prevents the
"works in the console, not in state" class of production incidents.

## Treatment & residual rationale

Severity-classified evaluation of the Terraform plan on a persistent schedule,
with an ignore list for expected drift and fail-closed handling, converts
silent divergence into alertable, tracked findings. Residual risk is the
window between the CI plan-refresh cadence and detection, plus drift below the
configured threshold that is accepted by policy.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Production incidents when a later apply reverts undocumented emergency changes
- Unauthorized changes that never surface in change control or version history
