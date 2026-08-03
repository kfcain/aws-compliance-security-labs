# Risk Register Entry — Supply Chain Risk, SBOM & Third-Party Monitoring

| Field | Value |
|-------|-------|
| Risk ID | RISK-10-01 |
| Lab | `10-supply-chain-sbom` |
| Owner (role) | Supply Chain Risk Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | Medium / High |
| Residual likelihood / impact | Medium / Medium |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Compromised dependencies or vendors introduce undetected risk**

## Threat narrative

Vulnerable third-party packages or SaaS vendors introduce risk outside traditional scanning.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious or vulnerable packages enter via the registry |
| T1525 | Implant Internal Image | Tampered container images persist in mutable registries |

## Security program impact

SCRM and SBOM are now board-level and FedRAMP SCR theme requirements.

## Compliance impact

SCF TPM/VPM/AST; FedRAMP KSI-SCR-SRA/TPM; NIST 800-161 themes; PCI third-party; ISO supplier relationships.

## Financial / business impact

Supply-chain incidents (dependency compromise) can halt releases and trigger customer exit clauses. SBOM automation reduces questionnaire turnaround time.

## Treatment & residual rationale

Inspector coverage and registry floor (scan-on-push, immutable tags) block the common ingestion paths; sophisticated upstream compromise remains.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
