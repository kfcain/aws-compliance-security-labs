# Vulnerability Detection & Response (Inspector VDR)

> Lab folder / original repo: `lab-inspector-vdr`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Automate FedRAMP 20x KSI-AFR-VDR: continuous scanning with Amazon Inspector, N1–N5 severity SLAs, Security Hub aggregation, and remediation evidence.

**Primary risk:** Unpatched CVEs leading to breach and failed authorization

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Vulnerability management is a core continuous control. Without severity SLAs and evidence, the program cannot prove risk reduction. |
| Compliance | FedRAMP 20x KSI-AFR-VDR requires N1–N5 severity ratings and remediation timelines. Maps to SCF VPM-01/02, NIST RA/SI families, PCI DSS 6.3.x, ISO 27001 A.8.8. |
| Financial / $$ | Unpatched critical CVEs are a top breach vector. Authorization delays cost months of sales cycles. Automated VDR cuts scanner-to-ticket latency and auditor prep cost. |
| Likelihood × Impact | High × Critical |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** Inspector, Security Hub, EventBridge, Lambda, Systems Manager, S3, SNS


## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `VPM-01`, `VPM-02`, `MON-01`, `THR-01` |
| FedRAMP 20x KSI | `KSI-AFR-VDR`, `KSI-AFR-PVL`, `KSI-MLA-EVC` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
02-inspector-vdr/
  README.md
  RISK.md
  SPEC.md
  scf/lab-spec.json
  diagrams/architecture.tldr
  infrastructure/template.yaml
  src/handler.py
```

## Quick start

1. Work from `labs/02-inspector-vdr/` in this monorepo (or use the original `lab-inspector-vdr` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

> **Note:** the crosswalk tables embedded in `index.html` are a static
> 2026-08-01 snapshot for the walkthrough page. `scf/scf-mapping.generated.json`
> is the canonical crosswalk; regenerate the page from it rather than editing HTML.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
