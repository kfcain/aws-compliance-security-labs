# Security Policy

## Scope

This repository contains **reference implementations** of AWS compliance and
security lab patterns. The code is intended for deployment into isolated
sandbox accounts. Nothing here is a hosted service, and no lab should be
pointed at production data or production identity providers.

## Reporting a vulnerability

If you find a security issue in any lab (an IAM policy that grants more than
it should, an injection path in a script, a control check that fails open,
a template that deploys an insecure default), please open a
[GitHub security advisory](https://github.com/kfcain/aws-compliance-security-labs/security/advisories/new)
or email the maintainer. Please do not open a public issue for anything you
believe is exploitable.

You can expect an acknowledgement within 7 days.

## Design commitments

The labs are held to the same standards they teach:

- **Fail closed.** An unconfigured or partially configured lab must report
  `CONFIG_ERROR`, never `PASS`. Demo/simulation data is only used when a
  caller explicitly requests simulation mode, and evidence artifacts are
  stamped with their data source.
- **Least privilege.** Lambda roles are scoped to named resources; wildcard
  resources require an inline, justified exception.
- **No plaintext secrets.** Credentials are read from AWS Secrets Manager.
  Environment variables carry ARNs and configuration, not secret material.
- **Encrypted evidence.** Evidence buckets, topics, queues, tables, and log
  groups are encrypted with customer-managed KMS keys; bucket policies deny
  non-TLS access.
- **Destructive actions are opt-in.** Anything that deletes data (lab 11) or
  modifies IAM (lab 14) ships in dry-run mode behind an explicit
  CloudFormation parameter.

## Supported versions

Only the `main` branch is maintained. Exported standalone `lab-*` repositories
are snapshots; report issues against this monorepo.
