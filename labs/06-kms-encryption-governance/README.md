# KMS Encryption & Secrets Governance

> Lab folder / original repo: `lab-kms-encryption-governance`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Enforce encryption at rest/in transit with customer-managed KMS keys, FIPS endpoints, key rotation, and Secrets Manager policy gates.

**Primary risk:** Unencrypted data exposure and cryptographic non-conformance

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Cryptographic governance underpins confidentiality commitments and customer trust. |
| Compliance | FedRAMP KSI-SVC-ENC/SNT; SCF CRY-01/03; NIST SC-13/SC-28; PCI DSS 3.x/4.x crypto; ISO 27001 crypto controls. |
| Financial / $$ | Encryption failures trigger breach notification laws and contract liabilities. FIPS gaps block federal deals. |
| Likelihood × Impact | Medium × Critical |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** KMS, Secrets Manager, Config, CloudTrail, Lambda, S3, ACM


## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `CRY-01`, `CRY-03`, `CFG-02`, `CLD-01` |
| FedRAMP 20x KSI | `KSI-SVC-ENC`, `KSI-SVC-SNT`, `KSI-SVC-SEC` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
06-kms-encryption-governance/
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

1. Work from `labs/06-kms-encryption-governance/` in this monorepo (or use the original `lab-kms-encryption-governance` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

> **Note:** the crosswalk tables embedded in `index.html` are a static
> 2026-08-01 snapshot for the walkthrough page. `scf/scf-mapping.generated.json`
> is the canonical crosswalk; regenerate the page from it rather than editing HTML.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
