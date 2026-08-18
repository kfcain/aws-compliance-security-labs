# Supply Chain Risk, SBOM & Third-Party Monitoring

> Lab folder / original repo: `lab-supply-chain-sbom`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Generate and store SBOMs, scan container/images with Inspector, track third-party SaaS risk, and feed continuous evidence for FedRAMP KSI-SCR.

**Primary risk:** Compromised dependencies or vendors introduce undetected risk

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | SCRM and SBOM are now board-level and FedRAMP SCR theme requirements. |
| Compliance | SCF TPM/VPM/AST; FedRAMP KSI-SCR-SRA/TPM; NIST 800-161 themes; PCI third-party; ISO supplier relationships. |
| Financial / $$ | Supply-chain incidents (dependency compromise) can halt releases and trigger customer exit clauses. SBOM automation reduces questionnaire turnaround time. |
| Likelihood × Impact | Medium × High |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** Inspector, ECR, CodePipeline, S3, EventBridge, Lambda, Security Hub, DynamoDB
- **External:** Vendor risk questionnaire / GRC

## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `TPM-01`, `TPM-03`, `TPM-04`, `VPM-01`, `AST-02` |
| FedRAMP 20x KSI | `KSI-SCR-SRA`, `KSI-SCR-TPM`, `KSI-AFR-VDR` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
10-supply-chain-sbom/
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

1. Work from `labs/10-supply-chain-sbom/` in this monorepo (or use the original `lab-supply-chain-sbom` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

> **Note:** the crosswalk tables embedded in `index.html` are a static
> 2026-08-01 snapshot for the walkthrough page. `scf/scf-mapping.generated.json`
> is the canonical crosswalk; regenerate the page from it rather than editing HTML.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
