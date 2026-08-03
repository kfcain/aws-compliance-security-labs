# Non-Human Identity Credential & Token Rotation

> Lab folder / original repo: `lab-nhi-credential-rotation`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Discover, inventory, and rotate service accounts, IAM access keys, API tokens, and workload identities on a policy cadence with break-glass evidence.

**Primary risk:** Long-lived machine credentials enabling lateral movement

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Non-human identities often outnumber humans 10:1+. Without inventory and rotation, secrets sprawl defeats IAM hygiene. |
| Compliance | SCF IAC-15/21, FedRAMP KSI-SVC-SEC / KSI-IAM-JIT, NIST IA/AC, PCI DSS 8.6.x key management expectations, ISO crypto and access themes. |
| Financial / $$ | Leaked CI/CD tokens cause multi-environment compromise. Rotation automation reduces emergency key-revocation fire drills and insurance questionnaire findings. |
| Likelihood × Impact | High × High |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** IAM, Secrets Manager, KMS, EventBridge, Lambda, CloudTrail, DynamoDB, SNS
- **External:** Okta Machine Auth, Descope M2M

## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `IAC-15`, `IAC-21`, `CRY-01`, `CFG-02` |
| FedRAMP 20x KSI | `KSI-IAM-ELP`, `KSI-IAM-JIT`, `KSI-SVC-SEC` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
03-nhi-credential-rotation/
  README.md
  RISK.md
  SPEC.md
  scf/lab-spec.json
  diagrams/architecture.tldr
  infrastructure/template.yaml
  src/handler.py
```

## Quick start

1. Work from `labs/03-nhi-credential-rotation/` in this monorepo (or use the original `lab-nhi-credential-rotation` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

> **Note:** the crosswalk tables embedded in `index.html` are a static
> 2026-08-01 snapshot for the walkthrough page. `scf/scf-mapping.generated.json`
> is the canonical crosswalk; regenerate the page from it rather than editing HTML.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
