# Risk Methodology

This defines the scales and vocabulary used by every lab's `RISK.md` and the
portfolio register (`RISKS.md`). Ratings without a defined scale are noise;
these definitions make the register auditable.

## Likelihood (probability of occurrence within 12 months)

| Rating | Definition |
|--------|------------|
| Very Low | < 5% — requires multiple independent failures or a targeted, resourced adversary |
| Low | 5–20% — plausible but requires uncommon conditions |
| Medium | 20–50% — expected occasionally given normal operations and threat activity |
| High | 50–80% — expected to occur; commonly observed in comparable environments |
| Very High | > 80% — occurring now or near-certain without intervention |

## Impact (worst credible outcome)

| Rating | Definition |
|--------|------------|
| Very Low | Negligible: no data exposure, no compliance effect, minor rework |
| Low | Limited: single-system disruption, findings closed within a normal cycle |
| Medium | Moderate: degraded control operation, repeat audit findings, bounded data exposure |
| High | Serious: authorization risk (ATO delay/conditions), reportable exposure, material contract impact |
| Critical | Severe: loss of authorization, federal data breach, contract termination, regulatory action |

## Risk bands (likelihood × impact)

Scored on the 5×5 grid; bands drive escalation:

- **Severe** (≥ High × Critical): executive visibility, treatment plan within 7 days
- **Major** (High×High, Medium×Critical): named owner, treatment in the current quarter
- **Moderate** (Medium×Medium..High, Low×Critical): tracked in the register, standard cadence
- **Minor** (everything below): monitor; accept with documented rationale allowed

## Inherent vs residual

**Inherent** = likelihood/impact with no lab automation in place (industry
base rates, the environment's exposure).
**Residual** = with this lab's controls operating as designed — continuous
validation, fail-closed evidence, alerting, and (where applicable) automated
response. Residual ratings assume the lab's CI keeps the control healthy;
each `RISK.md` documents the rationale for the delta.

## Treatment vocabulary

| Decision | Meaning |
|----------|---------|
| Mitigate | Reduce likelihood and/or impact via controls (the default for these labs) |
| Accept | Documented decision to carry the residual risk; requires owner + review date |
| Transfer | Contractual/insurance shift; residual operational risk stays on the register |
| Avoid | Eliminate the activity that creates the exposure |

## Review cadence

Every entry carries `Reviewed` and `Next review` dates. Cadence: 6 months,
or immediately after (a) a relevant incident, (b) a control regression caught
by CI, or (c) a framework change (e.g., FedRAMP KSI revision).

## MITRE ATT&CK usage

Each risk lists the primary ATT&CK techniques its threat narrative maps to
(Enterprise matrix, cloud-focused). The chain threat → technique → SCF
control → lab automation is what makes the register actionable rather than
descriptive.
