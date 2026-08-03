"""Cross-template invariants for all 15 lab stacks.

These are the repo's own guardrails on top of cfn-lint/checkov: partition
hygiene, tagging, DLQ/retry coverage, scoped IAM, and the status-contract
wiring that previously routed a residual-data FAIL to Succeed.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent
TEMPLATES = sorted(ROOT.glob("labs/*/infrastructure/template.yaml"))

# Wildcard-resource IAM statements that are legitimately unscopable. Every
# entry must carry an adjacent YAML comment justifying it in the template.
WILDCARD_SID_ALLOWLIST = {
    "XRayTracing",
    "ReadConfigCompliance",
    "ReadSecurityHubFindings",
    "ReadIamCredentialInventory",
    "ReadSecretsRotationPosture",
    "ReadGuardDutyPosture",
    "ReadKeyGovernancePosture",
    "ReadTrailPosture",
    "ReadNetworkPosture",
    "ReadInspectorPosture",
    "ReadRegistryPosture",
    "ReadBackupPosture",
    "ReadBackupInventory",
    "ReadInventorySources",
    "VendedLogDelivery",
    "EnableIamPolicies",       # KMS key policy root statement (standard pattern)
    "AllowCloudWatchLogs",     # KMS key policy service grant (condition-scoped)
    "AllowEventBridgeDlqDelivery",  # KMS key policy service grant (condition-scoped)
}


class _CfnLoader(yaml.SafeLoader):
    """Parse CloudFormation short-form tags into inspectable structures."""


def _multi(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {f"Fn::{tag_suffix}": loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {f"Fn::{tag_suffix}": loader.construct_sequence(node, deep=True)}
    return {f"Fn::{tag_suffix}": loader.construct_mapping(node, deep=True)}


_CfnLoader.add_multi_constructor("!", _multi)


def _load(path: Path) -> dict:
    return yaml.load(path.read_text(), Loader=_CfnLoader)


def _resources(template: dict, type_name: str) -> dict:
    return {
        name: res
        for name, res in template.get("Resources", {}).items()
        if res.get("Type") == type_name
    }


@pytest.fixture(scope="module", params=TEMPLATES, ids=[t.parent.parent.name for t in TEMPLATES])
def template(request):
    return request.param, _load(request.param)


def test_fifteen_templates_exist():
    assert len(TEMPLATES) == 15


def test_no_hardcoded_aws_partition(template):
    path, _ = template
    text = path.read_text()
    # arn:aws: literals break GovCloud; ${AWS::Partition} is required.
    assert not re.search(r"arn:aws:", text), f"{path}: hardcoded arn:aws: partition"


def test_serverless_function_packaging(template):
    path, doc = template
    functions = _resources(doc, "AWS::Serverless::Function")
    assert functions, f"{path}: no AWS::Serverless::Function"
    assert doc.get("Transform") == "AWS::Serverless-2016-10-31"
    for name, fn in functions.items():
        props = fn["Properties"]
        assert props["CodeUri"] == "../src", f"{path}:{name} must package ../src"
        assert props["Handler"] == "handler.handler"
        assert props["Runtime"] == "python3.13"
        assert props["Tracing"] == "Active"
        assert "ReservedConcurrentExecutions" in props
        assert "DeadLetterQueue" in props
        assert "KmsKeyArn" in props
        env = props["Environment"]["Variables"]
        for var in ("EVIDENCE_BUCKET", "SNS_TOPIC_ARN", "LAB_ID", "LOG_LEVEL"):
            assert var in env, f"{path}:{name} missing env {var}"
        assert env["LAB_ID"] == path.parent.parent.name


def test_no_inline_zipfile_stubs(template):
    path, _ = template
    assert "ZipFile" not in path.read_text(), f"{path}: inline code stub present"


def test_evidence_bucket_hardening(template):
    path, doc = template
    buckets = _resources(doc, "AWS::S3::Bucket")
    assert "EvidenceBucket" in buckets, f"{path}: evidence bucket must be stack-managed"
    for name, bucket in buckets.items():
        props = bucket["Properties"]
        pab = props["PublicAccessBlockConfiguration"]
        assert all(pab[k] for k in (
            "BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets",
        )), f"{path}:{name} public access block incomplete"
        assert "BucketEncryption" in props, f"{path}:{name} unencrypted"
        assert props["VersioningConfiguration"]["Status"] == "Enabled"
        assert "LifecycleConfiguration" in props


def test_tls_only_bucket_policies(template):
    path, doc = template
    policies = _resources(doc, "AWS::S3::BucketPolicy")
    buckets = set(_resources(doc, "AWS::S3::Bucket"))
    covered = set()
    for policy in policies.values():
        statements = policy["Properties"]["PolicyDocument"]["Statement"]
        has_tls_deny = any(
            s.get("Effect") == "Deny"
            and s.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport") == "false"
            for s in statements
        )
        bucket_ref = policy["Properties"]["Bucket"]
        if has_tls_deny and isinstance(bucket_ref, dict):
            covered.add(bucket_ref.get("Fn::Ref") or bucket_ref.get("Ref"))
    missing = buckets - covered
    assert not missing, f"{path}: buckets without TLS-only policy: {missing}"


def test_sns_encrypted_and_alert_email_wired(template):
    path, doc = template
    topics = _resources(doc, "AWS::SNS::Topic")
    assert topics, f"{path}: no SNS topic"
    for name, topic in topics.items():
        assert "KmsMasterKeyId" in topic["Properties"], f"{path}:{name} unencrypted"
    assert _resources(doc, "AWS::SNS::Subscription"), f"{path}: AlertEmail subscription missing"
    assert "AlertEmail" in doc.get("Parameters", {})


def test_log_groups_have_retention_and_cmk(template):
    path, doc = template
    groups = _resources(doc, "AWS::Logs::LogGroup")
    assert groups, f"{path}: no explicit log group"
    for name, group in groups.items():
        props = group["Properties"]
        assert "RetentionInDays" in props, f"{path}:{name} retention unset"
        assert "KmsKeyId" in props, f"{path}:{name} not CMK-encrypted"


def test_kms_key_rotation(template):
    path, doc = template
    keys = _resources(doc, "AWS::KMS::Key")
    assert keys, f"{path}: no CMK"
    for name, key in keys.items():
        assert key["Properties"]["EnableKeyRotation"] is True, f"{path}:{name} rotation off"


def test_event_rules_have_retry_and_dlq(template):
    path, doc = template
    rules = _resources(doc, "AWS::Events::Rule")
    for name, rule in rules.items():
        for target in rule["Properties"].get("Targets", []):
            assert "RetryPolicy" in target, f"{path}:{name} target lacks RetryPolicy"
            assert "DeadLetterConfig" in target, f"{path}:{name} target lacks DLQ"


def test_lambda_permissions_scoped(template):
    path, doc = template
    perms = _resources(doc, "AWS::Lambda::Permission")
    for name, perm in perms.items():
        props = perm["Properties"]
        assert "SourceArn" in props, f"{path}:{name} missing SourceArn"
        assert "SourceAccount" in props, f"{path}:{name} missing SourceAccount"


def _iter_statements(role_props):
    for policy in role_props.get("Policies", []):
        for statement in policy["PolicyDocument"]["Statement"]:
            if isinstance(statement, dict) and "Fn::If" in statement:
                branch = statement["Fn::If"][1]
                if isinstance(branch, dict):
                    yield branch
            elif isinstance(statement, dict):
                yield statement


def test_iam_wildcards_are_allowlisted(template):
    path, doc = template
    for role_name, role in _resources(doc, "AWS::IAM::Role").items():
        for statement in _iter_statements(role["Properties"]):
            resource = statement.get("Resource")
            if resource == "*" or (isinstance(resource, list) and "*" in resource):
                sid = statement.get("Sid", "<missing Sid>")
                assert sid in WILDCARD_SID_ALLOWLIST, (
                    f"{path}:{role_name}: wildcard Resource in statement {sid} "
                    "is not on the justified allowlist"
                )


def test_roles_have_trust_conditions_and_no_managed_lambda_policy(template):
    path, doc = template
    for role_name, role in _resources(doc, "AWS::IAM::Role").items():
        props = role["Properties"]
        for statement in props["AssumeRolePolicyDocument"]["Statement"]:
            assert "Condition" in statement, f"{path}:{role_name} trust lacks Condition"
        for arn in props.get("ManagedPolicyArns", []) or []:
            rendered = json.dumps(arn)
            assert "AWSLambdaBasicExecutionRole" not in rendered, (
                f"{path}:{role_name} uses the broad managed logs policy"
            )


def test_all_taggable_resources_tagged(template):
    path, doc = template
    taggable = (
        "AWS::S3::Bucket", "AWS::SNS::Topic", "AWS::SQS::Queue", "AWS::KMS::Key",
        "AWS::IAM::Role", "AWS::Logs::LogGroup", "AWS::DynamoDB::Table",
        "AWS::StepFunctions::StateMachine", "AWS::EC2::VPC",
    )
    for name, res in doc.get("Resources", {}).items():
        if res.get("Type") in taggable:
            tags = res["Properties"].get("Tags")
            assert tags, f"{path}:{name} has no Tags"
            keys = {
                t["Key"] for t in tags
                if isinstance(t, dict) and isinstance(t.get("Key"), str)
            }
            assert "project" in keys and "lab_id" in keys, (
                f"{path}:{name} missing standard tags"
            )


def test_outputs_have_description_and_export(template):
    path, doc = template
    outputs = doc.get("Outputs", {})
    assert outputs, f"{path}: no Outputs"
    for name, output in outputs.items():
        assert "Description" in output, f"{path}:{name} output lacks Description"
        assert "Export" in output, f"{path}:{name} output lacks Export"


def test_securityhub_import_scoped_to_own_product():
    """The finding-injection surface: BatchImportFindings must be scoped to
    the account's own default product ARN, never '*'."""
    for path in TEMPLATES:
        doc = _load(path)
        for role in _resources(doc, "AWS::IAM::Role").values():
            for statement in _iter_statements(role["Properties"]):
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if "securityhub:BatchImportFindings" in actions:
                    rendered = json.dumps(statement.get("Resource"))
                    assert "product/${AWS::AccountId}/default" in rendered, (
                        f"{path}: BatchImportFindings not scoped to own product ARN"
                    )


def test_lab11_state_machine_contract():
    """Regression: the Choice previously keyed off transport statusCode (200
    even on FAIL), routing residual-data failures to Succeed."""
    doc = _load(ROOT / "labs/11-federal-data-deletion-residual/infrastructure/template.yaml")
    machines = _resources(doc, "AWS::StepFunctions::StateMachine")
    assert machines
    sm = next(iter(machines.values()))["Properties"]
    assert sm["LoggingConfiguration"]["Level"] == "ALL"
    assert sm["TracingConfiguration"]["Enabled"] is True
    definition = json.dumps(sm["DefinitionString"])
    assert "compliance_status" in definition
    assert "statusCode" not in definition
    assert "sns:publish" in definition
    assert "Retry" in definition and "Catch" in definition


def test_lab11_destructive_iam_gated_and_scoped():
    doc = _load(ROOT / "labs/11-federal-data-deletion-residual/infrastructure/template.yaml")
    text = (ROOT / "labs/11-federal-data-deletion-residual/infrastructure/template.yaml").read_text()
    # The broken hardcoded guardrail key must not come back on S3 actions,
    # and destructive statements must be conditional.
    role = _resources(doc, "AWS::IAM::Role")["LabFunctionRole"]
    raw_statements = role["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    destructive = [s for s in raw_statements if isinstance(s, dict) and "Fn::If" in s]
    assert len(destructive) >= 3, "destructive statements must be gated behind Fn::If"
    for statement in destructive:
        branch = statement["Fn::If"][1]
        actions = branch.get("Action", [])
        if "s3:DeleteObjectVersion" in actions:
            # Scoped to a concrete bucket ARN — ResourceTag conditions do not
            # apply to S3 object actions (the original defect).
            assert "Condition" not in branch
            assert "FederalDataBucket" in json.dumps(branch["Resource"])
        if "backup:DeleteRecoveryPoint" in actions:
            assert branch["Condition"]["StringEquals"]["aws:ResourceTag/federal_data_lab"] == "true"
    assert "DeletionProtectionEnabled" in text
    table = _resources(doc, "AWS::DynamoDB::Table")["DeletionCaseTable"]["Properties"]
    assert table["SSESpecification"]["SSEType"] == "KMS"
    assert table["PointInTimeRecoverySpecification"]["PointInTimeRecoveryEnabled"] is True
