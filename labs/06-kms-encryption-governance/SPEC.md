# Specification — KMS Encryption & Secrets Governance

## Goal

Enforce encryption at rest/in transit with customer-managed KMS keys, FIPS endpoints, key rotation, and Secrets Manager policy gates.

## Non-goals

- Full enterprise GRC platform replacement
- Production multi-region DR (extend in a follow-on lab)
- Legal advice — map controls via SCF, validate with your assessor

## Functional requirements

1. Ingest signals from: KMS, Secrets Manager, Config, CloudTrail
2. Evaluate control objective on a persistent schedule (default: daily)
3. Emit machine-readable evidence JSON (and optional human summary)
4. Open or update a Security Hub finding / SNS alert on failure
5. Tag every evidence object with SCF IDs and FedRAMP 20x KSIs

## Acceptance criteria

- [ ] `sam build && sam deploy` provisions the stack; `cfn-lint` and `checkov` pass
- [ ] Handler returns `compliance_status` from real posture; unconfigured input yields `CONFIG_ERROR` (never `PASS`)
- [ ] A known-bad fixture drives `FAIL` with a Security Hub finding and SNS alert; a clean fixture drives `PASS`
- [ ] Evidence JSON is written to the KMS-encrypted evidence bucket with `data_source` stamped
- [ ] `pytest labs/06-kms-encryption-governance` passes (regression + behavior tests)
- [ ] Crosswalk, coverage, OSCAL, and assessment artifacts regenerate without drift

## Evidence schema (minimum)

```json
{
  "lab_id": "06-kms-encryption-governance",
  "checked_at": "ISO-8601",
  "status": "PASS|FAIL|ERROR|CONFIG_ERROR|NOT_APPLICABLE",
  "scf_controls": ["CRY-01","CRY-03","CFG-02","CLD-01"],
  "fedramp_20x_ksi": ["KSI-SVC-ENC","KSI-SVC-SNT","KSI-SVC-SEC"],
  "artifacts": []
}
```

## Security requirements

- Least-privilege Lambda role
- Encrypt evidence bucket with CMK
- No long-lived secrets in code — use Secrets Manager
- CloudTrail enabled on the account under test

## Threat model

Primary adversary objective and the technique this lab detects/mitigates are
enumerated with MITRE ATT&CK IDs in [RISK.md](./RISK.md). The control's
detection logic (`src/handler.py`) is the mitigation; the assessment
procedure in [ASSESSMENT.md](./ASSESSMENT.md) is how an assessor confirms it
operates. Primary technique: **T1552**.

Trust boundary: the worker runs with a least-privilege role in the account
under test, reads posture via AWS APIs (or the IdP API for lab 01), and writes
only to its own KMS-encrypted evidence bucket and SNS topic. Event input is
validated; caller-supplied fields never override a control decision.
