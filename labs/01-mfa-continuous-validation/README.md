# Persistent MFA Validation (Okta / Descope)

> Lab folder / original repo: `lab-mfa-continuous-validation`  
> Portfolio: AWS Compliance & Security Labs · SCF cross-framework mapping · FedRAMP 20x / CR26 KSIs

## Problem

Continuously validate phishing-resistant MFA enrollment and use for human identities via Okta or Descope, correlated with AWS IAM Identity Center and CloudTrail.

**Primary risk:** Account takeover from missing or bypassed MFA

## Why this matters

| Lens | Detail |
|------|--------|
| Security program | Identity is the primary control plane. Gaps in MFA break zero-trust and privileged access programs. |
| Compliance | Required by NIST 800-171 03.05.03, NIST 800-53 IA-2(1)/(2), PCI DSS 8.4.x, FedRAMP KSI-IAM-MFA, and ISO 27001 Annex A access controls via SCF IAC-06. |
| Financial / $$ | Average account-takeover breach cost often exceeds $4M+ (industry reports). Failed FedRAMP/CMMC/PCI assessments block revenue and contracts. Manual MFA audits burn GRC hours every quarter. |
| Likelihood × Impact | High × Critical |

## Architecture

Open the dark-mode tldraw diagram:

- [`diagrams/architecture.tldr`](./diagrams/architecture.tldr) — open in [tldraw.com](https://www.tldraw.com/) (File → Open) or any tldraw-compatible viewer
- Preview notes: [`diagrams/README.md`](./diagrams/README.md)

**Pattern:** Data sources → detection/aggregation (GuardDuty / Config / Inspector / Security Hub) → EventBridge → Lambda → Evidence & Alerts

### Services

- **AWS:** IAM Identity Center, CloudTrail, EventBridge, Lambda, Security Hub, SNS, DynamoDB
- **External:** Okta, Descope

## SCF controls & FedRAMP 20x KSIs

| Kind | IDs |
|------|-----|
| SCF | `IAC-06`, `IAC-15`, `IAC-21`, `MON-01` |
| FedRAMP 20x KSI | `KSI-IAM-MFA`, `KSI-IAM-ELP`, `KSI-AFR-PVL` |

Generate live crosswalks (NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP Rev5):

```bash
node ../../shared/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json
```

## Lab layout

```
01-mfa-continuous-validation/
  README.md
  RISK.md
  SPEC.md
  scf/lab-spec.json
  diagrams/architecture.tldr
  infrastructure/template.yaml
  src/handler.py
```

## Quick start

1. Work from `labs/01-mfa-continuous-validation/` in this monorepo (or use the original `lab-mfa-continuous-validation` repo).
2. Deploy `infrastructure/template.yaml` (SAM/CloudFormation) into a sandbox account.
3. Replace `src/handler.py` placeholders with IdP/API calls and Security Hub finding imports.
4. Run the SCF mapper and attach `scf-mapping.generated.json` to your evidence package.
5. Keep the EventBridge schedule at least every 3 days for FedRAMP 20x *persistent* machine validation.

> **Note:** the crosswalk tables embedded in `index.html` are a static
> 2026-08-01 snapshot for the walkthrough page. `scf/scf-mapping.generated.json`
> is the canonical crosswalk; regenerate the page from it rather than editing HTML.

## Related labs

See [`../catalog.json`](../catalog.json) and the portfolio root README.
