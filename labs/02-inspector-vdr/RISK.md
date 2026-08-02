# Risk statement — Vulnerability Detection & Response (Inspector VDR)

## Statement

**Unpatched CVEs leading to breach and failed authorization**

## Threat narrative

Known CVEs on EC2, containers, and Lambda remain unpatched past SLA windows.

## Security program impact

Vulnerability management is a core continuous control. Without severity SLAs and evidence, the program cannot prove risk reduction.

## Compliance impact

FedRAMP 20x KSI-AFR-VDR requires N1–N5 severity ratings and remediation timelines. Maps to SCF VPM-01/02, NIST RA/SI families, PCI DSS 6.3.x, ISO 27001 A.8.8.

## Financial / business impact

Unpatched critical CVEs are a top breach vector. Authorization delays cost months of sales cycles. Automated VDR cuts scanner-to-ticket latency and auditor prep cost.

## Rating

| Factor | Value |
|--------|-------|
| Likelihood | High |
| Impact | Critical |
| Suggested treatment | Automate detection + evidence; escalate residual risk to GRC risk register |

## Residual risk if untreated

- Repeat audit findings and delayed ATO / customer questionnaires
- Higher cyber-insurance premiums and possible coverage exclusions
- Increased probability of reportable breach and contract loss
