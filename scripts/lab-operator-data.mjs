/**
 * Operator playbooks for every lab: configure, collect evidence, document.
 * Consumed by scripts/build-walkthroughs.mjs and scripts/build-learn.mjs.
 * Content is derived from infrastructure/template.yaml Parameters and
 * src/handler.py contracts — keep in sync when those files change.
 */
export const SHARED_PARAMETERS = [
  { name: 'AlertEmail', default: '(empty)', meaning: 'SNS subscription. Empty means no email subscription. Confirm the SNS subscription from the mailbox after deploy.' },
  { name: 'ScheduleExpression', default: 'rate(1 day)', meaning: 'EventBridge cadence. FedRAMP 20x persistent validation hint: at most rate(3 days).' },
  { name: 'LogRetentionDays', default: '365', meaning: 'CloudWatch Logs retention for the worker.' },
  { name: 'EnableObjectLock', default: 'false', meaning: 'WORM on the evidence bucket. You can set this only at bucket creation.' },
  { name: 'ObjectLockRetentionDays', default: '365', meaning: 'GOVERNANCE-mode retention when Object Lock is on.' },
  { name: 'PermissionsBoundaryArn', default: '(empty)', meaning: 'Optional IAM permissions boundary on the worker role.' },
  { name: 'EnvironmentName', default: 'sandbox', meaning: 'Tag on every resource. Use a sandbox account.' },
  { name: 'OwnerTag', default: 'security-engineering', meaning: 'Owner tag on every resource.' },
];

export const STACK_OUTPUTS = [
  'FunctionArn',
  'EvidenceBucketName',
  'TopicArn',
  'LabKmsKeyArn',
  'DeadLetterQueueArn',
];

/** @typedef {{ checks: string, uniqueParameters: {name:string,default:string,meaning:string}[], extraOutputs?: string[], prerequisites: string[], configure: string[], configureCli?: string, liveEvent: {label:string, json:string}, evidenceLooksAt: string[], documentNotes: string[], warnings: string[] }} LabOp */

/** @type {Record<string, LabOp>} */
export const LAB_OPS = {
  '01-mfa-continuous-validation': {
    checks: 'Every active human identity in Okta or Descope has phishing-resistant MFA (WebAuthn / U2F / Okta FastPass signed_nonce). Missing or SMS-only factors yield FAIL.',
    uniqueParameters: [
      { name: 'IdpProvider', default: 'okta', meaning: 'okta or descope.' },
      { name: 'OktaDomain', default: '(empty)', meaning: 'Bare hostname such as example.okta.com. Empty yields CONFIG_ERROR at runtime.' },
      { name: 'IdpSecretArn', default: '(empty)', meaning: 'Secrets Manager ARN for the IdP admin token. Do not put the token in Lambda environment variables.' },
    ],
    prerequisites: [
      'Use a sandbox Okta or Descope tenant. Do not point this lab at a production identity provider.',
      'Store the IdP token in Secrets Manager before deploy. The stack reads IdpSecretArn.',
      'Enable Security Hub in the region so FAIL can import an ASFF finding.',
    ],
    configure: [
      'Create a Secrets Manager secret with the IdP API token.',
      'Deploy with IdpProvider, OktaDomain, and IdpSecretArn set.',
      'Confirm an unconfigured run (empty OktaDomain) returns CONFIG_ERROR, never PASS.',
    ],
    configureCli: `export IDP_TOKEN='replace-with-sandbox-okta-token'
aws secretsmanager create-secret --name aws-lab-01/idp-token --secret-string "$IDP_TOKEN"
SECRET_ARN=$(aws secretsmanager describe-secret --secret-id aws-lab-01/idp-token --query ARN --output text)
echo "sam deploy parameter IdpSecretArn=$SECRET_ARN"
echo "sam deploy parameter OktaDomain=example.okta.com"`,
    liveEvent: {
      label: 'Scheduled sweep (default). The worker pages the IdP user directory.',
      json: '{"source":"scheduled-sweep"}',
    },
    evidenceLooksAt: [
      'identities[] with mfa_enabled, phishing_resistant, and factor types',
      'data_source is okta or descope for live runs, simulation only when mode=simulation',
      'FAIL identities also appear as Security Hub findings',
    ],
    documentNotes: [
      'Attach the evidence JSON plus the IdP MFA policy excerpt (no tokens).',
      'Record OktaDomain (hostname only) and that the token came from Secrets Manager.',
    ],
    warnings: [
      'The handler refuses non-https IdP URLs and does not follow redirects, so a poisoned OKTA_DOMAIN cannot leak the token.',
    ],
  },
  '02-inspector-vdr': {
    checks: 'Inspector/Security Hub findings are scored on the N1–N5 SLA matrix. Overdue remediation yields FAIL.',
    uniqueParameters: [],
    prerequisites: [
      'Enable Amazon Inspector in the account/region.',
      'Enable Security Hub and the Inspector integration so findings flow.',
    ],
    configure: [
      'Deploy the stack. There are no extra lab parameters.',
      'The stack also listens for Security Hub finding events, not only the daily schedule.',
    ],
    liveEvent: {
      label: 'Scheduled sweep pulls findings from Security Hub. Finding events also invoke the worker.',
      json: '{"source":"scheduled-sweep"}',
    },
    evidenceLooksAt: [
      'findings[] with severity band N1–N5, first_observed, sla_due, remediated',
      'overdue findings drive FAIL',
    ],
    documentNotes: [
      'Attach the evidence JSON and the Inspector/Security Hub finding IDs that missed SLA.',
      'State the N1–N5 windows you use in the ATO package if they differ from the lab defaults (1/7/30/90/180 days).',
    ],
    warnings: ['Zero Inspector coverage is a control gap. CONFIG_ERROR or FAIL — never a silent PASS.'],
  },
  '03-nhi-credential-rotation': {
    checks: 'IAM access keys and Secrets Manager secrets older than MaxKeyAgeDays, or secrets with rotation disabled, yield FAIL.',
    uniqueParameters: [
      { name: 'MaxKeyAgeDays', default: '90', meaning: 'Maximum age for keys and for last secret rotation/change.' },
    ],
    prerequisites: [
      'The worker lists IAM users/keys and Secrets Manager secrets. Deploy only in a sandbox if you do not want that inventory in evidence.',
    ],
    configure: [
      'Set MaxKeyAgeDays to the rotation policy in your SSP (often 90).',
      'Optional: invoke with a pre-built inventory from an external NHI platform instead of live AWS discovery.',
    ],
    liveEvent: {
      label: 'Empty event = live IAM + Secrets Manager discovery. Or supply inventory from Okta/Descope M2M.',
      json: '{"inventory":[{"type":"iam_access_key","principal":"arn:aws:iam::123456789012:user/svc","credential_id":"AKIA...","created_at":"2024-01-01T00:00:00Z"}]}',
    },
    evidenceLooksAt: [
      'credentials[] with age_days, rotation_enabled, over_age',
      'data_source is aws-api, event, or simulation',
    ],
    documentNotes: [
      'Attach the evidence JSON and the written rotation policy (MaxKeyAgeDays).',
      'Do not paste secret values. credential_id in evidence is an identifier only.',
    ],
    warnings: ['Malformed created_at on any item is ERROR for the whole population. The lab does not PASS a partial inventory.'],
  },
  '04-config-drift-compliance': {
    checks: 'AWS Config recorder must be recording. Any NON_COMPLIANT rule is drift (FAIL). INSUFFICIENT_DATA never passes silently. Zero rules is CONFIG_ERROR.',
    uniqueParameters: [
      { name: 'EnableConfigRules', default: 'false', meaning: 'When true, the stack creates example Config rules (encryption, CloudTrail, root keys). Default off because Config rules can be account-wide.' },
    ],
    prerequisites: [
      'A configuration recorder must exist and be recording, or the worker returns CONFIG_ERROR.',
    ],
    configure: [
      'Leave EnableConfigRules=false if the account already has a Config pack.',
      'Set EnableConfigRules=true only in a sandbox that has no conflicting rules.',
    ],
    configureCli: `aws configservice describe-configuration-recorders
aws configservice describe-configuration-recorder-status
# Recording must be true. A stopped recorder is CONFIG_ERROR.`,
    liveEvent: {
      label: 'Scheduled sweep. Config compliance-change events also invoke the worker.',
      json: '{"source":"scheduled-sweep"}',
    },
    evidenceLooksAt: [
      'recorders[] recording=true',
      'rules[] ComplianceType',
      'PASS requires at least one COMPLIANT rule and zero NON_COMPLIANT',
    ],
    documentNotes: [
      'Attach evidence JSON and the Config rule pack name or EnableConfigRules setting.',
      'Explain INSUFFICIENT_DATA items — they are not PASS.',
    ],
    warnings: ['A stopped recorder means the control is not operating. That is CONFIG_ERROR, not PASS.'],
  },
  '05-guardduty-automated-response': {
    checks: 'At least one GuardDuty detector must exist and be ENABLED. Active findings at or above SeverityThreshold in LookbackDays yield FAIL.',
    uniqueParameters: [
      { name: 'EnableGuardDutyDetector', default: 'false', meaning: 'Account singleton. Default off so the stack does not create a second detector.' },
      { name: 'SeverityThreshold', default: '7', meaning: 'GuardDuty severity 1–10. Default 7 is high.' },
      { name: 'LookbackDays', default: '7', meaning: 'Only findings updated in this window fail the control.' },
    ],
    prerequisites: [
      'Prefer an existing detector. Set EnableGuardDutyDetector=true only if the account has none.',
    ],
    configure: [
      'Deploy with EnableGuardDutyDetector=false when GuardDuty is already on.',
      'Tune SeverityThreshold to the SOC playbook.',
    ],
    configureCli: `aws guardduty list-detectors --output table
# If none exist, set EnableGuardDutyDetector=true only in this sandbox.`,
    liveEvent: {
      label: 'Scheduled sweep of unarchived findings. GuardDuty finding events also invoke the worker.',
      json: '{"source":"scheduled-sweep"}',
    },
    evidenceLooksAt: [
      'detectors[] Status=ENABLED',
      'findings[] at or above threshold',
    ],
    documentNotes: [
      'Attach evidence JSON, detector ID, and the threshold you used.',
      'Map FAIL findings to the IR lab (09) if you automate response.',
    ],
    warnings: ['No detector is CONFIG_ERROR. A disabled detector is FAIL.'],
  },
  '06-kms-encryption-governance': {
    checks: 'Every enabled symmetric CMK must rotate annually and must not have an unconditioned Principal:* Allow. Secrets Manager secrets must rotate and must be within MaxSecretAgeDays. Zero keys and zero secrets is NOT_APPLICABLE.',
    uniqueParameters: [
      { name: 'MaxSecretAgeDays', default: '90', meaning: 'Maximum age since last secret rotation or change.' },
    ],
    prerequisites: [
      'The worker lists KMS keys and secrets in the account/region.',
    ],
    configure: [
      'Set MaxSecretAgeDays to the cryptographic policy in the SSP.',
    ],
    liveEvent: {
      label: 'Scheduled sweep of CMKs and secrets.',
      json: '{"source":"scheduled-sweep"}',
    },
    evidenceLooksAt: [
      'keys[] rotation and policy findings',
      'secrets[] rotation_enabled and age',
    ],
    documentNotes: [
      'Attach evidence JSON. Do not copy key policies that contain account data you cannot share.',
      'If the region has no CMKs and no secrets, document NOT_APPLICABLE with the empty inventory.',
    ],
    warnings: ['AWS-managed keys are out of scope. The lab governs customer-managed symmetric keys.'],
  },
  '07-cloudtrail-evidence-pipeline': {
    checks: 'At least one CloudTrail trail is logging with log-file validation, a multi-region trail, KMS encryption, and an immutable trail bucket (Object Lock + versioning + encryption + public-access block). The lab evidence bucket is checked the same way.',
    uniqueParameters: [
      { name: 'EnableTrail', default: 'false', meaning: 'Creates a trail + Object-Lock log bucket. Default off because an account may already have an organization trail.' },
      { name: 'TrailObjectLockDays', default: '365', meaning: 'Object Lock retention on the trail bucket when EnableTrail=true.' },
    ],
    extraOutputs: ['TrailBucketName'],
    prerequisites: [
      'Do not create a second account trail if an organization trail already covers the account, unless the assessor wants a dedicated evidence trail.',
    ],
    configure: [
      'Set EnableTrail=true only when you need the lab to own the trail.',
      'Enable Object Lock on the evidence bucket if the assessor requires WORM for the JSON artifacts too.',
    ],
    liveEvent: {
      label: 'Scheduled sweep of trail and bucket posture.',
      json: '{"source":"scheduled-sweep"}',
    },
    evidenceLooksAt: [
      'trails[] IsLogging, LogFileValidationEnabled, IsMultiRegionTrail, KMSKeyId',
      'bucket immutability for each trail bucket and EVIDENCE_BUCKET',
    ],
    documentNotes: [
      'Attach evidence JSON, trail ARN, and bucket Object Lock settings.',
      'This lab proves the audit path exists. It does not replace Athena query workpapers.',
    ],
    warnings: ['No trail is FAIL. The account has no audit pipeline.'],
  },
  '08-vpc-network-segmentation': {
    checks: 'Every VPC has an ACTIVE flow log. No security group may allow 0.0.0.0/0 or ::/0 to SSH/RDP or via IpProtocol=-1. World-open 443 on an ALB is not a violation of this lab.',
    uniqueParameters: [],
    extraOutputs: ['SegmentedVpcId'],
    prerequisites: [
      'The stack creates a sample segmented VPC with flow logs. The worker still evaluates EVERY VPC in the region.',
    ],
    configure: [
      'Deploy the stack. There are no extra lab parameters.',
      'Expect FAIL if other VPCs in the region lack flow logs or have world-open SSH/RDP.',
    ],
    liveEvent: {
      label: 'Scheduled sweep of VPCs, flow logs, and security groups (paginated).',
      json: '{"source":"scheduled-sweep"}',
    },
    evidenceLooksAt: [
      'vpc_flow_coverage percent',
      'sensitive_ingress_violations[]',
    ],
    documentNotes: [
      'Attach evidence JSON and the network diagram for in-scope VPCs.',
      'If the sandbox has leftover default VPCs, either fix them or document them as out of assessment scope in lab 13.',
    ],
    warnings: ['Zero VPCs is NOT_APPLICABLE. Partial flow-log coverage is FAIL.'],
  },
  '09-incident-response-automation': {
    checks: 'Every SSM document in REQUIRED_RUNBOOKS exists and is Active. The SNS topic has at least one confirmed subscriber. Missing runbooks or zero subscribers yield FAIL. Empty REQUIRED_RUNBOOKS is CONFIG_ERROR.',
    uniqueParameters: [],
    extraOutputs: ['IsolateRunbookName'],
    prerequisites: [
      'Confirm the AlertEmail subscription (email confirm link) or the escalation check FAIL.',
    ],
    configure: [
      'Deploy the stack. It creates isolate and forensic-snapshot runbooks and sets REQUIRED_RUNBOOKS.',
      'Confirm the SNS email subscription before you collect a PASS.',
    ],
    configureCli: `TOPIC=$(aws cloudformation describe-stacks --stack-name aws-lab-09 \\
  --query "Stacks[0].Outputs[?OutputKey=='TopicArn'].OutputValue" --output text)
aws sns list-subscriptions-by-topic --topic-arn "$TOPIC"
# PendingConfirmation does not count. Confirm the email link first.`,
    liveEvent: {
      label: 'Scheduled readiness check. Security Hub findings also invoke the worker.',
      json: '{"source":"scheduled-sweep"}',
    },
    evidenceLooksAt: [
      'runbooks[] Status=Active',
      'escalation_subscribers > 0',
    ],
    documentNotes: [
      'Attach evidence JSON, SSM document names, and proof of the confirmed SNS subscription.',
      'This lab attests automation is invocable now. It is not a tabletop script.',
    ],
    warnings: ['Pending SNS subscriptions do not count. The subscriber must be confirmed.'],
  },
  '10-supply-chain-sbom': {
    checks: 'Inspector v2 scanning must be ENABLED for EC2 and ECR (and Lambda when present). Every ECR repository must scan-on-push and use IMMUTABLE tags.',
    uniqueParameters: [],
    prerequisites: [
      'Enable Inspector2 for ECR/EC2 in the region or the worker returns CONFIG_ERROR (often AccessDenied before enablement).',
    ],
    configure: [
      'Enable Inspector2, then deploy.',
      'Fix ECR repositories that still allow mutable tags.',
    ],
    configureCli: `aws inspector2 batch-get-account-status --output json
aws ecr describe-repositories --query 'repositories[].{name:repositoryName,mutability:imageTagMutability,scan:imageScanningConfiguration.scanOnPush}'`,
    liveEvent: {
      label: 'Scheduled sweep of Inspector2 account status and ECR repositories.',
      json: '{"source":"scheduled-sweep"}',
    },
    evidenceLooksAt: [
      'inspector resource-state ENABLED flags',
      'repositories[] scanOnPush and imageTagMutability',
    ],
    documentNotes: [
      'Attach evidence JSON and the SBOM/scan policy for the pipeline.',
      'AES256 on ECR is recorded as a warning, not a FAIL. CMK is preferred.',
    ],
    warnings: ['Inspector not activated is CONFIG_ERROR. The control cannot be evaluated.'],
  },
  '11-federal-data-deletion-residual': {
    checks: 'For a deletion case, purge is dry-run unless EnablePurgeActions=true. PASS requires a real residual scan of every cataloged S3/DynamoDB/Backup store with zero hits. RDS/OpenSearch need a manual check or the lab FAIL.',
    uniqueParameters: [
      { name: 'TenantTagKey', default: 'federal_tenant_id', meaning: 'Tag key used to find tenant backup recovery points.' },
      { name: 'EnablePurgeActions', default: 'false', meaning: 'Destructive deletes. Default off = DRY_RUN. Do not enable in a shared account.' },
      { name: 'RequireBackupPurge', default: 'true', meaning: 'Tenant-tagged recovery points must be in the catalog and scanned.' },
    ],
    prerequisites: [
      'Keep EnablePurgeActions=false until you have a sandbox tenant prefix you may delete.',
      'Supply a catalog of stores in the invoke event. An empty catalog outside simulation is CONFIG_ERROR.',
    ],
    configure: [
      'Deploy with EnablePurgeActions=false.',
      'Run a dry-run case first. Read the evidence. Only then consider EnablePurgeActions=true on a disposable prefix.',
    ],
    liveEvent: {
      label: 'Deletion case plus store catalog. simulate_residual_hits is ignored unless mode=simulation.',
      json: '{"case":{"tenant_id":"tenant-alpha","agency_id":"agency-x","reason":"offboarding","requested_at":"2026-08-01T00:00:00Z"},"catalog":[{"service":"s3","arn_or_name":"s3://federal-app-data/tenant-alpha/","backup_vault":"federal-vault"},{"service":"dynamodb","arn_or_name":"TenantData","tenant_key_attribute":"tenant_id","backup_vault":"federal-vault"}]}',
    },
    evidenceLooksAt: [
      'purge_actions[] with DRY_RUN vs completed',
      'residual_scan[] hits and unverified stores',
      'zero_residual_hits true only after a real scan',
    ],
    documentNotes: [
      'Attach evidence JSON, the case ID, and a statement that purge was dry-run or enabled.',
      'For RDS/OpenSearch, attach the manual residual-check workpaper. The lab will FAIL until that exists.',
    ],
    warnings: [
      'Placeholder purge results never count as deletion. ENABLE_PURGE default false.',
      'Do not enable purge against production prefixes.',
    ],
  },
  '12-backup-recovery-rto-rpo': {
    checks: 'Each critical asset must declare RTO/RPO, backup frequency <= RPO, vault encryption/lock, and a restore drill whose duration is <= RTO. An empty objectives list is CONFIG_ERROR — not an empty estate.',
    uniqueParameters: [
      { name: 'EnableVaultLock', default: 'false', meaning: 'AWS Backup vault lock is hard to reverse. Default off.' },
    ],
    prerequisites: [
      'You must supply the recovery-objective register in the event. AWS Backup APIs cannot invent RTO/RPO promises.',
    ],
    configure: [
      'Leave EnableVaultLock=false until the vault policy is approved.',
      'Prepare an objectives JSON that matches real assets.',
    ],
    liveEvent: {
      label: 'Recovery-objective register. last_restore_success must be a real boolean; the string false fails.',
      json: '{"objectives":[{"asset_id":"api-db","asset_arn":"arn:aws:rds:us-east-1:123456789012:db:api-db","criticality":"mission_critical","rto_minutes":60,"rpo_minutes":15,"backup_frequency_minutes":15,"vault_name":"main-vault","vault_locked":true,"encrypted_with_cmk":true,"last_restore_test_at":"2026-08-01T00:00:00Z","last_restore_duration_minutes":42,"last_restore_success":true}]}',
    },
    evidenceLooksAt: [
      'objectives[] alignment vs RTO/RPO',
      'drill success and duration',
    ],
    documentNotes: [
      'Attach evidence JSON, the signed RTO/RPO table, and the restore-drill ticket.',
      'Pair with lab 17 for Terraform state-backend DR. This lab is runtime backup/drill evidence.',
    ],
    warnings: ['Unreported last_restore_success on mission_critical assets fails the drill objective.'],
  },
  '13-boundary-asset-inventory': {
    checks: 'Every resource is classified in_boundary / inherited / out_of_boundary / unknown. Federal data stores must be in-boundary with owner and data-classification tags. No boundary in the event or ALLOWED_ACCOUNT_IDS is CONFIG_ERROR. Empty inventory outside simulation is CONFIG_ERROR.',
    uniqueParameters: [
      { name: 'EnableAggregator', default: 'false', meaning: 'Creates a Config aggregator (account/region singleton-ish). Default off.' },
      { name: 'EnableResourceExplorer', default: 'false', meaning: 'Creates Resource Explorer index/view. Default off.' },
    ],
    prerequisites: [
      'Supply event.boundary or set ALLOWED_ACCOUNT_IDS. There is no default account list.',
      'Supply event.inventory from Config/Resource Explorer. An empty feed means the sensor is broken.',
    ],
    configure: [
      'Enable aggregator/explorer only if the account does not already have them.',
      'Put the authorization-boundary account list in the invoke event (authoritative) or in ALLOWED_ACCOUNT_IDS.',
    ],
    liveEvent: {
      label: 'Boundary plus inventory. event.boundary can narrow ALLOWED_ACCOUNT_IDS; it cannot be spoofed away.',
      json: '{"boundary":{"system_name":"Federal SaaS CSO","mas_version":"2026.1","in_scope_account_ids":["111111111111"],"in_scope_services":["AWS::S3::Bucket"]},"inventory":[{"resource_id":"arn:aws:s3:::cso-tenant-data","resource_type":"AWS::S3::Bucket","account_id":"111111111111","region":"us-gov-west-1","tags":{"boundary_status":"in_boundary","federal_tenant_id":"agency-a","data_classification":"CUI","owner":"platform-team"},"processes_federal_data":true}]}',
    },
    evidenceLooksAt: [
      'inventory classification counts',
      'shadow / unknown federal-data resources (FAIL)',
      'evidence omits full tag maps on purpose',
    ],
    documentNotes: [
      'Attach evidence JSON and the signed authorization boundary (MAS).',
      'Explain every out_of_boundary resource that still processes federal data.',
    ],
    warnings: ['Missing inventory is CONFIG_ERROR, not “empty estate PASS”.'],
  },
  '14-privileged-suspend-lifecycle': {
    checks: 'Privilege is computed by detection, not by a caller privileged flag. When suspension is required, AUTO_SUSPEND=false (default) yields FAIL (dry-run), not a fake PASS. EnableSuspendActions must be true before the role can call IAM suspend APIs.',
    uniqueParameters: [
      { name: 'AutoSuspend', default: 'false', meaning: 'When false, the worker reports FAIL if suspension was required but not executed.' },
      { name: 'EnableSuspendActions', default: 'false', meaning: 'IAM policy gate for deactivate-key / deny-all attach. Default off.' },
      { name: 'MaxStandingPrivDays', default: '1', meaning: 'Standing-privilege review window.' },
    ],
    prerequisites: [
      'Keep both AutoSuspend and EnableSuspendActions false until you have a disposable IAM user/role in the sandbox.',
    ],
    configure: [
      'Deploy with both gates false. Collect dry-run FAIL evidence first.',
      'Only then enable the IAM actions and AutoSuspend on a test principal.',
    ],
    liveEvent: {
      label: 'Suspicious privileged activity. GuardDuty IAM findings also invoke the worker. Caller privileged:false cannot de-escalate.',
      json: '{"mode":"suspicious","principal":"arn:aws:iam::123456789012:user/break-glass","event_name":"ConsoleLogin"}',
    },
    evidenceLooksAt: [
      'is_privileged computed by the worker',
      'actions[] actually executed vs dry-run reason',
      'compliance_status FAIL when suspend was required but not done',
    ],
    documentNotes: [
      'Attach evidence JSON and the joiner/mover/leaver or GuardDuty event ID.',
      'State clearly whether AutoSuspend was on. Assessors treat a dry-run FAIL as the honest residual.',
    ],
    warnings: [
      'Do not enable suspend actions in an account with production IAM users.',
      'via_pipeline-style caller overrides are ignored here too: privileged on the event can only escalate.',
    ],
  },
  '15-immutable-cicd-change-control': {
    checks: 'Forbidden in-place APIs are allowed only from exact PIPELINE_ACTOR_ROLE_ARNS. via_pipeline on the event is ignored for the decision. Unset pipeline ARNs is CONFIG_ERROR. Pipeline actors still need a change_ticket or the control FAIL.',
    uniqueParameters: [
      { name: 'PipelineActorRoleArns', default: '(empty)', meaning: 'CSV of full IAM role ARNs for CodePipeline/CodeBuild deploy roles. Empty yields CONFIG_ERROR.' },
    ],
    prerequisites: [
      'Collect the real deploy role ARNs (account-aware). Substrings such as CodePipelineServiceRole are rejected.',
    ],
    configure: [
      'Deploy with PipelineActorRoleArns set to the exact deploy role ARN(s).',
      'Feed change_events from CloudTrail (StopLogging, PutBucketPolicy, console updates, and similar).',
    ],
    liveEvent: {
      label: 'Change events. via_pipeline:true from an attacker principal still FAIL.',
      json: '{"change_events":[{"event_name":"StopLogging","event_time":"2026-08-01T00:00:00Z","principal":"arn:aws:iam::999999999999:user/attacker","via_pipeline":true}]}',
    },
    evidenceLooksAt: [
      'via_pipeline computed from principal ARN match, claimed_via_pipeline recorded for forensics',
      'change_ticket present or missing',
    ],
    documentNotes: [
      'Attach evidence JSON, the pipeline role ARNs, and the change-ticket IDs for pipeline-originated forbidden APIs.',
      'Cross-account look-alike role names do not match. Document the exact ARNs.',
    ],
    warnings: ['Do not trust a caller-supplied via_pipeline boolean. The lab ignores it for the verdict.'],
  },
  '16-terraform-drift-detection': {
    checks: 'CI uploads terraform show -json (refresh-only) to the plan bucket. The worker classifies resource_drift by severity, applies DRIFT_IGNORE, and FAIL at or above FailSeverity. It does not auto-apply.',
    uniqueParameters: [
      { name: 'FailSeverity', default: 'high', meaning: 'critical|high|medium|low. Drift at or above this fails.' },
      { name: 'RemediationMode', default: 'report', meaning: 'report or dry_run. Recorded in evidence. No apply from Lambda.' },
    ],
    extraOutputs: ['PlanArtifactBucketName'],
    prerequisites: [
      'A CI job with Terraform credentials produces the plan JSON. The Lambda only reads it.',
      'See governance/collect-evidence.sh and governance/policy/drift.rego.',
    ],
    configure: [
      'Deploy the stack. Note PlanArtifactBucketName.',
      'In CI: terraform plan -refresh-only -out tfplan && terraform show -json tfplan > plan.json && aws s3 cp plan.json s3://$PLAN_BUCKET/...',
    ],
    configureCli: `PLAN_BUCKET=$(aws cloudformation describe-stacks --stack-name aws-lab-16 \\
  --query "Stacks[0].Outputs[?OutputKey=='PlanArtifactBucketName'].OutputValue" --output text)
terraform plan -refresh-only -out tfplan
terraform show -json tfplan > plan.json
aws s3 cp plan.json "s3://$PLAN_BUCKET/prod/tfplan.json"
# Optional: conftest test --policy governance/policy plan.json`,
    liveEvent: {
      label: 'Scheduled read of the latest plan object, or pass bucket/key in the event.',
      json: '{"plan_key":"prod/tfplan.json"}',
    },
    evidenceLooksAt: [
      'assurance case: provenance (terraform_commit, workspace, collector_role)',
      'evidence_manifest_sha256',
      'per-control objective→claim→status mapping',
      'drift[] severity after ignore list',
    ],
    documentNotes: [
      'Attach the evidence JSON (assurance case), the plan JSON hash, odp-register.yaml, and Conftest results.',
      'Run policy on the plan before apply and on the evidence after.',
    ],
    warnings: ['The Lambda never runs terraform apply. Remediation stays in gated CI.'],
  },
  '17-terraform-dr-readiness': {
    checks: 'CI uploads a DR descriptor derived from terraform show -json plus backend config. The worker checks state-backend resilience (versioning, encryption, replication, locking) and DR architecture parity against RTO/RPO. It does not execute failover.',
    uniqueParameters: [
      { name: 'FailSeverity', default: 'high', meaning: 'Severity floor for FAIL.' },
      { name: 'RtoTargetMinutes', default: '60', meaning: 'RTO ODP from the DR plan.' },
      { name: 'RpoTargetMinutes', default: '15', meaning: 'RPO ODP from the DR plan.' },
    ],
    extraOutputs: ['DescriptorBucketName'],
    prerequisites: [
      'Run governance/derive-descriptor.sh in CI against the Terraform workspace.',
      'Pair with lab 12 for restore-drill evidence. This lab is IaC/backend possibility, not a drill.',
    ],
    configure: [
      'Deploy with RtoTargetMinutes and RpoTargetMinutes from the signed DR plan.',
      'Upload the descriptor to DescriptorBucketName.',
    ],
    configureCli: `DESC_BUCKET=$(aws cloudformation describe-stacks --stack-name aws-lab-17 \\
  --query "Stacks[0].Outputs[?OutputKey=='DescriptorBucketName'].OutputValue" --output text)
# From labs/17-terraform-dr-readiness, derive then upload:
#   ./governance/derive-descriptor.sh > descriptor.json
aws s3 cp descriptor.json "s3://$DESC_BUCKET/prod/dr.json"`,
    liveEvent: {
      label: 'Scheduled read of the latest descriptor, or pass key in the event.',
      json: '{"descriptor_key":"prod/dr.json"}',
    },
    evidenceLooksAt: [
      'state backend versioning/encryption/replication/lock',
      'recovery region, failover routing, durable data',
      'assurance case with SHA-256 manifest and CP-family objectives',
    ],
    documentNotes: [
      'Attach evidence JSON, the descriptor, and the DR plan ODPs.',
      'State clearly that no failover was executed.',
    ],
    warnings: ['A local-file Terraform backend fails this lab. State is the control plane you recover from.'],
  },
};
