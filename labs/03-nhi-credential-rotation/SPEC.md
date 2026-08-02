# Specification — Non-Human Identity Credential & Token Rotation

## Goal

Discover, inventory, and rotate service accounts, IAM access keys, API tokens, and workload identities on a policy cadence with break-glass evidence.

## Non-goals

- Full enterprise GRC platform replacement
- Production multi-region DR (extend in a follow-on lab)
- Legal advice — map controls via SCF, validate with your assessor

## Functional requirements

1. Ingest signals from: IAM, Secrets Manager, KMS, EventBridge, Okta Machine Auth, Descope M2M
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
  "lab_id": "03-nhi-credential-rotation",
  "checked_at": "ISO-8601",
  "status": "PASS|FAIL|ERROR",
  "scf_controls": ["IAC-15","IAC-21","CRY-01","CFG-02"],
  "fedramp_20x_ksi": ["KSI-IAM-ELP","KSI-IAM-JIT","KSI-SVC-SEC"],
  "artifacts": []
}
```

## Security requirements

- Least-privilege Lambda role
- Encrypt evidence bucket with CMK
- No long-lived secrets in code — use Secrets Manager
- CloudTrail enabled on the account under test
