# Specification — Immutable Audit Evidence Pipeline

## Goal

Build an org-wide CloudTrail → S3 (Object Lock) → Athena/Security Lake pipeline that packages machine-readable evidence for FedRAMP 20x persistent validation.

## Non-goals

- Full enterprise GRC platform replacement
- Production multi-region DR (extend in a follow-on lab)
- Legal advice — map controls via SCF, validate with your assessor

## Functional requirements

1. Ingest signals from: CloudTrail, S3 Object Lock, EventBridge, Lambda
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
  "lab_id": "07-cloudtrail-evidence-pipeline",
  "checked_at": "ISO-8601",
  "status": "PASS|FAIL|ERROR",
  "scf_controls": ["MON-01","MON-02","CPL-02","CHG-01"],
  "fedramp_20x_ksi": ["KSI-MLA-OSM","KSI-AFR-PVL","KSI-CMT-CHG"],
  "artifacts": []
}
```

## Security requirements

- Least-privilege Lambda role
- Encrypt evidence bucket with CMK
- No long-lived secrets in code — use Secrets Manager
- CloudTrail enabled on the account under test
