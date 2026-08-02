# Specification — Persistent MFA Validation (Okta / Descope)

## Goal

Continuously validate phishing-resistant MFA enrollment and use for human identities via Okta or Descope, correlated with AWS IAM Identity Center and CloudTrail.

## Non-goals

- Full enterprise GRC platform replacement
- Production multi-region DR (extend in a follow-on lab)
- Legal advice — map controls via SCF, validate with your assessor

## Functional requirements

1. Ingest signals from: IAM Identity Center, CloudTrail, EventBridge, Lambda, Okta, Descope
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
  "lab_id": "01-mfa-continuous-validation",
  "checked_at": "ISO-8601",
  "status": "PASS|FAIL|ERROR",
  "scf_controls": ["IAC-06","IAC-15","IAC-21","MON-01"],
  "fedramp_20x_ksi": ["KSI-IAM-MFA","KSI-IAM-ELP","KSI-AFR-PVL"],
  "artifacts": []
}
```

## Security requirements

- Least-privilege Lambda role
- Encrypt evidence bucket with CMK
- No long-lived secrets in code — use Secrets Manager
- CloudTrail enabled on the account under test
