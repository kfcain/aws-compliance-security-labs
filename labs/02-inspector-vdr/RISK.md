# Risk Register Entry — Vulnerability Detection & Response (Inspector VDR)

| Field | Value |
|-------|-------|
| Risk ID | RISK-02-01 |
| Lab | `02-inspector-vdr` |
| Owner (role) | Vulnerability Management Lead |
| Treatment decision | Mitigate — automated by this lab's continuous validation |
| Inherent likelihood / impact | High / Critical |
| Residual likelihood / impact | Medium / High |
| Reviewed | 2026-08-03 |
| Next review | 2027-02-03 |

Ratings use the 5×5 scales defined in
[docs/RISK-METHODOLOGY.md](../../docs/RISK-METHODOLOGY.md). Residual assumes
this lab's controls are deployed and kept healthy by CI.

## Statement

**Unpatched CVEs leading to breach and failed authorization**

## Threat narrative

Known CVEs on EC2, containers, and Lambda remain unpatched past SLA windows.

## MITRE ATT&CK techniques

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1190 | Exploit Public-Facing Application | Unpatched CVEs on exposed workloads are the initial access path |
| T1195 | Supply Chain Compromise | Vulnerable dependencies enter through images and packages |

## Security program impact

Vulnerability management is a core continuous control. Without severity SLAs and evidence, the program cannot prove risk reduction.

## Compliance impact

FedRAMP 20x KSI-AFR-VDR requires N1–N5 severity ratings and remediation timelines. Maps to SCF VPM-01/02, NIST RA/SI families, PCI DSS 6.3.x, ISO 27001 A.8.8.

## Financial / business impact

Unpatched critical CVEs are a top breach vector. Authorization delays cost months of sales cycles. Automated VDR cuts scanner-to-ticket latency and auditor prep cost.

## Treatment & residual rationale

Paginated SLA sweeps with N1-N5 deadlines and alerting keep breaches visible and bounded; exploitation of a not-yet-patched CVE remains possible inside SLA windows.

## Consequences if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
