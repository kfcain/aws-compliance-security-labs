# Specification — Vulnerability Detection & Response (Inspector VDR)

## Goal

Automate FedRAMP 20x KSI-AFR-VDR: continuous scanning with Amazon Inspector, N1–N5 severity SLAs, Security Hub aggregation, and remediation evidence.

## Non-goals

- Full enterprise GRC platform replacement
- Production multi-region DR (extend in a follow-on lab)
- Legal advice — map controls via SCF, validate with your assessor

## Functional requirements

1. Ingest signals from: Inspector, Security Hub, EventBridge, Lambda
2. Evaluate control objective on a persistent schedule (default: daily)
3. Emit machine-readable evidence JSON (and optional human summary)
4. Open or update a Security Hub finding / SNS alert on failure
5. Tag every evidence object with SCF IDs and FedRAMP 20x KSIs

## Acceptance criteria

- [ ] Infrastructure deploys via `infrastructure/template.yaml`
- [ ] Lambda returns structured JSON with `lab_id`, `scf_controls`, `fedramp_20x_ksi`
- [ ] SCF mapper produces crosswalk file for target frameworks
- [ ] Architecture diagram opens in tldraw (dark background)
- [ ] RISK.md reviewed by security owner

## Evidence schema (minimum)

```json
{
  "lab_id": "02-inspector-vdr",
  "checked_at": "ISO-8601",
  "status": "PASS|FAIL|ERROR",
  "scf_controls": ["VPM-01","VPM-02","MON-01","THR-01"],
  "fedramp_20x_ksi": ["KSI-AFR-VDR","KSI-AFR-PVL","KSI-MLA-EVC"],
  "artifacts": []
}
```

## Security requirements

- Least-privilege Lambda role
- Encrypt evidence bucket with CMK
- No long-lived secrets in code — use Secrets Manager
- CloudTrail enabled on the account under test
