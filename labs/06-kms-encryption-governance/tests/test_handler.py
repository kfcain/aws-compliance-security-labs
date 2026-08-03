"""Behavior tests for lab 06 (KMS & secrets governance)."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("06-kms-encryption-governance")

CUSTOMER_KEY = {
    "KeyId": "key-1",
    "Arn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
    "KeyManager": "CUSTOMER",
    "KeySpec": "SYMMETRIC_DEFAULT",
    "Enabled": True,
}
SAFE_POLICY = (
    '{"Statement": [{"Sid": "Root", "Effect": "Allow", '
    '"Principal": {"AWS": "arn:aws:iam::123456789012:root"}, '
    '"Action": "kms:*", "Resource": "*"}]}'
)
PUBLIC_POLICY_NO_CONDITION = (
    '{"Statement": [{"Sid": "Open", "Effect": "Allow", "Principal": "*", '
    '"Action": "kms:Decrypt", "Resource": "*"}]}'
)
PUBLIC_POLICY_WITH_CONDITION = (
    '{"Statement": [{"Sid": "Scoped", "Effect": "Allow", "Principal": "*", '
    '"Action": "kms:Decrypt", "Resource": "*", '
    '"Condition": {"StringEquals": {"kms:CallerAccount": "123456789012"}}}]}'
)


def _kms(keys=None, rotation=True, policy=SAFE_POLICY):
    keys = keys if keys is not None else [CUSTOMER_KEY]
    return FakeClient(
        pages={"list_keys": [{"Keys": [{"KeyId": k["KeyId"]} for k in keys]}]},
        responses={
            "describe_key": lambda **kw: {
                "KeyMetadata": next(k for k in keys if k["KeyId"] == kw["KeyId"])
            },
            "get_key_rotation_status": {"KeyRotationEnabled": rotation},
            "get_key_policy": {"Policy": policy},
        },
    )


def _secrets(secret_list=None):
    return FakeClient(pages={"list_secrets": [{"SecretList": secret_list or []}]})


def _fresh_secret(**overrides):
    secret = {
        "Name": "db-cred",
        "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-cred",
        "RotationEnabled": True,
        "LastRotatedDate": datetime.now(UTC) - timedelta(days=10),
    }
    secret.update(overrides)
    return secret


def _invoke(event, lambda_context, kms=None, secrets=None):
    kms = kms or _kms()
    secrets = secrets or _secrets([_fresh_secret()])
    s3, sns = FakeClient(), FakeClient()
    hub = FakeClient(responses={"batch_import_findings": {"SuccessCount": 1}})
    result = handler_mod.handler(
        event, lambda_context,
        kms_client=kms, secretsmanager_client=secrets,
        s3_client=s3, sns_client=sns, securityhub_client=hub,
    )
    return result, s3, sns, hub


def test_healthy_key_and_secret_pass(lambda_context):
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "PASS"


def test_rotation_disabled_cmk_fails(lambda_context):
    result, _, sns, hub = _invoke({}, lambda_context, kms=_kms(rotation=False))
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert "rotation is disabled" in body["violations"][0]
    assert hub.calls_to("batch_import_findings") and sns.calls_to("publish")


def test_public_key_policy_no_condition_fails(lambda_context):
    result, *_ = _invoke({}, lambda_context, kms=_kms(policy=PUBLIC_POLICY_NO_CONDITION))
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert any('Principal "*"' in v for v in body["violations"])


def test_public_key_policy_with_condition_passes(lambda_context):
    result, *_ = _invoke({}, lambda_context, kms=_kms(policy=PUBLIC_POLICY_WITH_CONDITION))
    assert result["compliance_status"] == "PASS"


def test_aws_managed_and_asymmetric_keys_ignored(lambda_context):
    keys = [
        dict(CUSTOMER_KEY, KeyId="aws-managed", KeyManager="AWS"),
        dict(CUSTOMER_KEY, KeyId="rsa-signing", KeySpec="RSA_2048"),
    ]
    kms = _kms(keys=keys, rotation=False)  # rotation off would fail if evaluated
    result, *_ = _invoke({}, lambda_context, kms=kms)
    body = json.loads(result["body"])
    assert body["customer_managed_keys"]["count"] == 0
    assert result["compliance_status"] == "PASS"  # only the fresh secret remains


def test_stale_secret_fails(lambda_context):
    stale = _fresh_secret(
        Name="stale", RotationEnabled=True,
        LastRotatedDate=datetime.now(UTC) - timedelta(days=200),
    )
    result, *_ = _invoke({}, lambda_context, secrets=_secrets([stale]))
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert any("days ago" in v for v in body["violations"])


def test_rotation_disabled_secret_fails(lambda_context):
    result, *_ = _invoke(
        {}, lambda_context,
        secrets=_secrets([_fresh_secret(RotationEnabled=False)]),
    )
    assert result["compliance_status"] == "FAIL"


def test_empty_account_not_applicable(lambda_context):
    result, *_ = _invoke({}, lambda_context, kms=_kms(keys=[]), secrets=_secrets([]))
    assert result["compliance_status"] == "NOT_APPLICABLE"


def test_bad_age_env_is_config_error(lambda_context, monkeypatch):
    monkeypatch.setenv("MAX_SECRET_AGE_DAYS", "ninety")
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_simulation_is_stamped_and_fails(lambda_context):
    result, *_ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    assert result["compliance_status"] == "FAIL"


def test_evidence_written(lambda_context):
    result, s3, *_ = _invoke({}, lambda_context)
    assert s3.calls_to("put_object")
