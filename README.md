# AWS Compliance & Security Labs

Combined monorepo for `17` AWS compliance and security labs. Labs `01`–`15` were previously published as separate `lab-*` repositories under [`kfcain`](https://github.com/kfcain); labs `16`–`17` are new to this monorepo.

Target frameworks: **NIST SP 800-171**, **NIST SP 800-53**, **ISO 27001**, **PCI DSS**, and **FedRAMP 20x / CR26 Key Security Indicators (KSIs)**.

Cross-framework mapping uses the [Secure Controls Framework (SCF) static JSON API](https://grcengclub.github.io/scf-api/).

## Architecture pattern

```
Data sources (Flow Logs, CloudTrail, Config, Inspector, IdP)
        → GuardDuty / Config / Inspector / Security Hub
        → EventBridge → Lambda
        → Evidence & Alerts
```

## Repository layout

```
labs/                 # One folder per lab (01–17)
  catalog.json        # Machine-readable portfolio index
shared/scf-mapper/    # Shared SCF crosswalk CLI
shared/lambda-common/ # Vendored Lambda runtime (lab_common.py)
scripts/              # Portfolio + GRC generators (map-all, coverage, oscal, …)
```

Each lab includes `README.md`, `RISK.md`, `SPEC.md`, `ASSESSMENT.md`, `scf/`, `infrastructure/template.yaml`, `src/handler.py`, and `tests/`. Labs `01`–`15` also ship `diagrams/architecture.tldr` and a walkthrough `index.html`; labs `16`–`17` use an inline mermaid diagram in their README instead.

## Labs

| ID | Title | Primary risk | Original repo |
|----|-------|--------------|---------------|
| `01-mfa-continuous-validation` | [Persistent MFA Validation (Okta / Descope)](./labs/01-mfa-continuous-validation/) | Account takeover from missing or bypassed MFA | [`lab-mfa-continuous-validation`](https://github.com/kfcain/lab-mfa-continuous-validation) |
| `02-inspector-vdr` | [Vulnerability Detection & Response (Inspector VDR)](./labs/02-inspector-vdr/) | Unpatched CVEs leading to breach and failed authorization | [`lab-inspector-vdr`](https://github.com/kfcain/lab-inspector-vdr) |
| `03-nhi-credential-rotation` | [Non-Human Identity Credential & Token Rotation](./labs/03-nhi-credential-rotation/) | Long-lived machine credentials enabling lateral movement | [`lab-nhi-credential-rotation`](https://github.com/kfcain/lab-nhi-credential-rotation) |
| `04-config-drift-compliance` | [Continuous Config Drift & Control Status](./labs/04-config-drift-compliance/) | Silent configuration drift breaking baseline controls | [`lab-config-drift-compliance`](https://github.com/kfcain/lab-config-drift-compliance) |
| `05-guardduty-automated-response` | [GuardDuty Threat Detection & Automated Response](./labs/05-guardduty-automated-response/) | Delayed response to active compromise increases blast radius | [`lab-guardduty-automated-response`](https://github.com/kfcain/lab-guardduty-automated-response) |
| `06-kms-encryption-governance` | [KMS Encryption & Secrets Governance](./labs/06-kms-encryption-governance/) | Unencrypted data exposure and cryptographic non-conformance | [`lab-kms-encryption-governance`](https://github.com/kfcain/lab-kms-encryption-governance) |
| `07-cloudtrail-evidence-pipeline` | [Immutable Audit Evidence Pipeline](./labs/07-cloudtrail-evidence-pipeline/) | Inability to prove who did what — audit failure and legal exposure | [`lab-cloudtrail-evidence-pipeline`](https://github.com/kfcain/lab-cloudtrail-evidence-pipeline) |
| `08-vpc-network-segmentation` | [VPC Network Segmentation & Flow Visibility](./labs/08-vpc-network-segmentation/) | Flat networks enable lateral movement and PCI scope expansion | [`lab-vpc-network-segmentation`](https://github.com/kfcain/lab-vpc-network-segmentation) |
| `09-incident-response-automation` | [Incident Response Automation Playbooks](./labs/09-incident-response-automation/) | Ad-hoc IR increases dwell time, cost, and regulatory penalties | [`lab-incident-response-automation`](https://github.com/kfcain/lab-incident-response-automation) |
| `10-supply-chain-sbom` | [Supply Chain Risk, SBOM & Third-Party Monitoring](./labs/10-supply-chain-sbom/) | Compromised dependencies or vendors introduce undetected risk | [`lab-supply-chain-sbom`](https://github.com/kfcain/lab-supply-chain-sbom) |
| `11-federal-data-deletion-residual` | [Federal Data Deletion & Residual-Data Proof (Class C)](./labs/11-federal-data-deletion-residual/) | Federal customer data remains after offboarding or spill cleanup | [`lab-federal-data-deletion-residual`](https://github.com/kfcain/lab-federal-data-deletion-residual) |
| `12-backup-recovery-rto-rpo` | [Backup Alignment & Recovery Testing (RTO/RPO)](./labs/12-backup-recovery-rto-rpo/) | Unproven backups leave federal missions unrestorable after ransomware or outage | [`lab-backup-recovery-rto-rpo`](https://github.com/kfcain/lab-backup-recovery-rto-rpo) |
| `13-boundary-asset-inventory` | [Authorization Boundary & Real-Time Asset Inventory](./labs/13-boundary-asset-inventory/) | Unknown or out-of-scope resources silently process federal data | [`lab-boundary-asset-inventory`](https://github.com/kfcain/lab-boundary-asset-inventory) |
| `14-privileged-suspend-lifecycle` | [Privileged Suspend & Account Lifecycle Automation](./labs/14-privileged-suspend-lifecycle/) | Orphaned or compromised privileged access to federal systems | [`lab-privileged-suspend-lifecycle`](https://github.com/kfcain/lab-privileged-suspend-lifecycle) |
| `15-immutable-cicd-change-control` | [Immutable CI/CD Change Control & Deployment Validation](./labs/15-immutable-cicd-change-control/) | Untracked production changes bypass review and corrupt federal workloads | [`lab-immutable-cicd-change-control`](https://github.com/kfcain/lab-immutable-cicd-change-control) |
| `16-terraform-drift-detection` | [Terraform State Drift Detection & Remediation Governance](./labs/16-terraform-drift-detection/) | Out-of-band changes drift Terraform-managed infrastructure away from its declared baseline | — (new; drift model adapted from [`tfdrift`](https://github.com/sudarshan8417/tfdrift)) |
| `17-terraform-dr-readiness` | [Terraform DR Readiness & State-Backend Resilience](./labs/17-terraform-dr-readiness/) | A disaster is unrecoverable because the Terraform state backend or declared architecture is not DR-ready | — (new) |

## Quick start

```bash
# Verify everything offline (Node 18+; Python dev tools from requirements-dev.txt)
pip install -r requirements-dev.txt
make lint test iac check     # ruff, pytest, node --test, cfn-lint, checkov, drift gates

# Deploy one lab (packages the real handler in src/ — python3.13 runtime)
cd labs/04-config-drift-compliance
sam build -t infrastructure/template.yaml
sam deploy --guided          # parameters gate optional/singleton resources

# Regenerate SCF crosswalks (live network; otherwise the scheduled
# scf-refresh workflow does this in CI)
SCF_LIVE=1 npm run scf:map:all
```

Every stack creates and hardens its own evidence bucket (SSE-KMS CMK,
versioning, TLS-only policy, optional Object Lock), encrypts SNS/SQS/logs
with the lab CMK, sets explicit log retention, wires `AlertEmail` to an SNS
subscription, and scopes IAM to named resources with partition-agnostic ARNs
(GovCloud-deployable). Destructive or account-singleton resources (GuardDuty
detectors, CloudTrail trails, Config rules/aggregators, purge permissions,
IAM suspend actions, Backup vault lock) are gated behind parameters that
default **off**.

Open a lab's `diagrams/architecture.tldr` (labs 01–15) in [tldraw.com](https://www.tldraw.com/) (File → Open); labs 16–17 render their architecture inline in the README.

## Original split repos

This monorepo consolidates the following public repositories (still available individually):

- [lab-mfa-continuous-validation](https://github.com/kfcain/lab-mfa-continuous-validation)
- [lab-inspector-vdr](https://github.com/kfcain/lab-inspector-vdr)
- [lab-nhi-credential-rotation](https://github.com/kfcain/lab-nhi-credential-rotation)
- [lab-config-drift-compliance](https://github.com/kfcain/lab-config-drift-compliance)
- [lab-guardduty-automated-response](https://github.com/kfcain/lab-guardduty-automated-response)
- [lab-kms-encryption-governance](https://github.com/kfcain/lab-kms-encryption-governance)
- [lab-cloudtrail-evidence-pipeline](https://github.com/kfcain/lab-cloudtrail-evidence-pipeline)
- [lab-vpc-network-segmentation](https://github.com/kfcain/lab-vpc-network-segmentation)
- [lab-incident-response-automation](https://github.com/kfcain/lab-incident-response-automation)
- [lab-supply-chain-sbom](https://github.com/kfcain/lab-supply-chain-sbom)
- [lab-federal-data-deletion-residual](https://github.com/kfcain/lab-federal-data-deletion-residual)
- [lab-backup-recovery-rto-rpo](https://github.com/kfcain/lab-backup-recovery-rto-rpo)
- [lab-boundary-asset-inventory](https://github.com/kfcain/lab-boundary-asset-inventory)
- [lab-privileged-suspend-lifecycle](https://github.com/kfcain/lab-privileged-suspend-lifecycle)
- [lab-immutable-cicd-change-control](https://github.com/kfcain/lab-immutable-cicd-change-control)

## License

MIT
