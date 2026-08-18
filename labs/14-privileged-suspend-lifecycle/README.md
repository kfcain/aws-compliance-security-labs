# Privileged Suspend & Account Lifecycle Automation

> Lab folder / original repo: `lab-privileged-suspend-lifecycle`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Automate joiner/mover/leaver for human and privileged identities, and auto-disable or contain privileged access on suspicious activity (KSI-IAM-SUS / KSI-IAM-AAM).

**Primary risk:** Orphaned or compromised privileged access to federal systems

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Privileged Access Management and automated lifecycle are mandatory for zero-trust. Suspend-on-suspicion closes the MFA gap after credential theft. |
| Compliance | FedRAMP KSI-IAM-SUS, KSI-IAM-AAM, KSI-IAM-ELP/JIT/APM; SCF IAC-15/16/17/21; NIST AC/IA; PCI 7.x/8.x; ISO access control. |
| Financial / $$ | Privileged misuse drives the highest-impact breaches. Automation cuts MTTC and reduces standing-privilege audit findings that block deals. |
| Likelihood × Impact | High × Critical |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** IAM, IAM Identity Center, CloudTrail, GuardDuty, EventBridge, Lambda, Step Functions, Security Hub, SNS, DynamoDB
- **External:** Okta, Descope

## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `IAC-15`, `IAC-16`, `IAC-17`, `IAC-21`, `MON-01`, `THR-03` |
| FedRAMP 20x KSI | `KSI-IAM-SUS`, `KSI-IAM-AAM`, `KSI-IAM-ELP`, `KSI-IAM-JIT`, `KSI-IAM-APM` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
14-privileged-suspend-lifecycle/
  README.md
  RISK.md
  SPEC.md
  scf/lab-spec.json
  diagrams/architecture.tldr
  infrastructure/template.yaml
  src/handler.py
```

## Operator walkthrough

Configure the stack, collect evidence, and assemble the assessor package:
[WALKTHROUGH.md](./WALKTHROUGH.md). Shared steps:
[operator playbook](../../docs/walkthroughs/00-operator-playbook.md).

## Quick start

1. Work from `labs/14-privileged-suspend-lifecycle/` in this monorepo (or use the original `lab-privileged-suspend-lifecycle` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

> **Note:** the crosswalk tables embedded in `index.html` are a static
> 2026-08-01 snapshot for the walkthrough page. `scf/scf-mapping.generated.json`
> is the canonical crosswalk; regenerate the page from it rather than editing HTML.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
