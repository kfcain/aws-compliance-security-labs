"""Behavior tests for lab 10 (supply chain, SBOM & third-party monitoring)."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("10-supply-chain-sbom")

ENABLED_ACCOUNT = {
    "accountId": "123456789012",
    "resourceState": {"ec2": {"status": "ENABLED"}, "ecr": {"status": "ENABLED"}},
}
HARDENED_REPO = {
    "repositoryName": "api",
    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/api",
    "imageScanningConfiguration": {"scanOnPush": True},
    "imageTagMutability": "IMMUTABLE",
    "encryptionConfiguration": {"encryptionType": "KMS"},
}


def _invoke(event, lambda_context, *, accounts=None, repo_pages=None, inspector=None):
    inspector = inspector or FakeClient(responses={
        "batch_get_account_status": {"accounts": accounts or [ENABLED_ACCOUNT]},
    })
    ecr = FakeClient(pages={"describe_repositories": repo_pages or [{"repositories": [HARDENED_REPO]}]})
    s3, sns = FakeClient(), FakeClient()
    hub = FakeClient(responses={"batch_import_findings": {"SuccessCount": 1}})
    result = handler_mod.handler(
        event, lambda_context,
        inspector2_client=inspector, ecr_client=ecr,
        s3_client=s3, sns_client=sns, securityhub_client=hub,
    )
    return result, ecr, s3, sns, hub


def test_all_hardened_passes(lambda_context):
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "PASS"


def test_scanning_disabled_fails(lambda_context):
    accounts = [{
        "accountId": "123456789012",
        "resourceState": {"ec2": {"status": "DISABLED"}, "ecr": {"status": "ENABLED"}},
    }]
    result, _, _, sns, hub = _invoke({}, lambda_context, accounts=accounts)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert body["violations"][0]["type"] == "inspector_scanning_disabled"
    assert hub.calls_to("batch_import_findings") and sns.calls_to("publish")


def test_mutable_tags_fail(lambda_context):
    repo = dict(HARDENED_REPO, imageTagMutability="MUTABLE")
    result, *_ = _invoke({}, lambda_context, repo_pages=[{"repositories": [repo]}])
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert "IMMUTABLE" in body["violations"][0]["detail"]


def test_scan_on_push_off_fails(lambda_context):
    repo = dict(HARDENED_REPO, imageScanningConfiguration={"scanOnPush": False})
    result, *_ = _invoke({}, lambda_context, repo_pages=[{"repositories": [repo]}])
    assert result["compliance_status"] == "FAIL"


def test_aes256_is_warning_not_violation(lambda_context):
    repo = dict(HARDENED_REPO, encryptionConfiguration={"encryptionType": "AES256"})
    result, *_ = _invoke({}, lambda_context, repo_pages=[{"repositories": [repo]}])
    body = json.loads(result["body"])
    assert result["compliance_status"] == "PASS"
    assert body["warning_count"] == 1


def test_zero_repos_passes_on_inspector_alone(lambda_context):
    result, *_ = _invoke({}, lambda_context, repo_pages=[{"repositories": []}])
    body = json.loads(result["body"])
    assert result["compliance_status"] == "PASS"
    assert body["repositories"]["status"] == "NOT_APPLICABLE"


def test_inspector_not_activated_is_config_error(lambda_context):
    inspector = FakeClient(responses={"batch_get_account_status": ClientError(
        {"Error": {"Code": "AccessDeniedException"}}, "BatchGetAccountStatus")})
    result, *_ = _invoke({}, lambda_context, inspector=inspector)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_repo_pagination(lambda_context):
    soft = dict(HARDENED_REPO, repositoryName="soft", imageTagMutability="MUTABLE")
    pages = [{"repositories": [HARDENED_REPO]}, {"repositories": [soft]}]
    result, *_ = _invoke({}, lambda_context, repo_pages=pages)
    body = json.loads(result["body"])
    assert body["repositories"]["count"] == 2
    assert result["compliance_status"] == "FAIL"


def test_simulation_is_stamped(lambda_context):
    result, *_ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    assert result["compliance_status"] == "FAIL"  # sim dataset includes a soft repo


def test_evidence_written(lambda_context):
    result, _, s3, *_ = _invoke({}, lambda_context)
    assert s3.calls_to("put_object")
