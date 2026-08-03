"""Behavior tests for lab 04 (continuous Config drift & control status).

Headline regression: the previous handler returned PASS_PLACEHOLDER without
calling AWS Config at all. Every verdict here comes from real (faked) API
shapes: recorder status, rule inventory, and per-rule compliance.
"""
from __future__ import annotations

import json

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("04-config-drift-compliance")

RECORDING = {
    "ConfigurationRecordersStatus": [
        {"name": "default", "recording": True, "lastStatus": "SUCCESS"},
    ]
}


def _rule(name):
    return {"ConfigRuleName": name, "Source": {"SourceIdentifier": name.upper()},
            "ConfigRuleState": "ACTIVE"}


def _compliance(name, kind):
    return {"ConfigRuleName": name, "Compliance": {"ComplianceType": kind}}


def _config_client(*, recorder=None, rules_pages=None, compliance_pages=None):
    return FakeClient(
        responses={"describe_configuration_recorder_status": recorder or RECORDING},
        pages={
            "describe_config_rules": rules_pages
            or [{"ConfigRules": [_rule("restricted-ssh")]}],
            "describe_compliance_by_config_rule": compliance_pages
            or [{"ComplianceByConfigRules": [_compliance("restricted-ssh", "COMPLIANT")]}],
        },
    )


def _invoke(event, lambda_context, config=None):
    config = config or _config_client()
    s3 = FakeClient()
    sns = FakeClient()
    securityhub = FakeClient(responses={"batch_import_findings": {"SuccessCount": 1}})
    result = handler_mod.handler(
        event, lambda_context,
        config_client=config, securityhub_client=securityhub,
        s3_client=s3, sns_client=sns,
    )
    return result, config, s3, sns, securityhub


def test_recorder_not_recording_is_config_error(lambda_context):
    """Recorder off means the control is not operating — never PASS."""
    config = _config_client(recorder={"ConfigurationRecordersStatus": [
        {"name": "default", "recording": False, "lastStatus": "FAILURE"},
    ]})
    result, *_ = _invoke({}, lambda_context, config)
    assert result["compliance_status"] == "CONFIG_ERROR"
    assert "recording" in json.loads(result["body"])["error"]


def test_no_recorder_is_config_error(lambda_context):
    config = _config_client(recorder={"ConfigurationRecordersStatus": []})
    result, *_ = _invoke({}, lambda_context, config)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_noncompliant_rule_fails_with_names_and_alerts(lambda_context):
    config = _config_client(
        rules_pages=[{"ConfigRules": [_rule("restricted-ssh"), _rule("iam-mfa")]}],
        compliance_pages=[{"ComplianceByConfigRules": [
            _compliance("restricted-ssh", "NON_COMPLIANT"),
            _compliance("iam-mfa", "COMPLIANT"),
        ]}],
    )
    result, _, _, sns, securityhub = _invoke({}, lambda_context, config)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert body["non_compliant_rules"] == ["restricted-ssh"]
    assert body["counts"]["non_compliant"] == 1
    assert sns.calls_to("publish"), "FAIL must alert"
    assert securityhub.calls_to("batch_import_findings"), "FAIL must import an ASFF finding"


def test_all_compliant_passes_without_alert(lambda_context):
    result, _, _, sns, securityhub = _invoke({}, lambda_context)
    assert result["compliance_status"] == "PASS"
    body = json.loads(result["body"])
    assert body["counts"]["non_compliant"] == 0
    assert body["data_source"] == "aws-api"
    assert not sns.calls_to("publish")
    assert not securityhub.calls_to("batch_import_findings")


def test_zero_rules_is_config_error(lambda_context):
    config = _config_client(rules_pages=[{"ConfigRules": []}])
    result, *_ = _invoke({}, lambda_context, config)
    assert result["compliance_status"] == "CONFIG_ERROR"
    assert "no Config rules" in json.loads(result["body"])["error"]


def test_insufficient_data_only_never_passes_silently(lambda_context):
    """Rules that have never evaluated COMPLIANT cannot demonstrate the
    control operates — fail closed and surface the rule names."""
    config = _config_client(
        rules_pages=[{"ConfigRules": [_rule("restricted-ssh")]}],
        compliance_pages=[{"ComplianceByConfigRules": [
            _compliance("restricted-ssh", "INSUFFICIENT_DATA"),
        ]}],
    )
    result, *_ = _invoke({}, lambda_context, config)
    assert result["compliance_status"] == "FAIL"
    body = json.loads(result["body"])
    assert body["insufficient_data_rules"] == ["restricted-ssh"]


def test_insufficient_data_reported_alongside_pass(lambda_context):
    config = _config_client(
        rules_pages=[{"ConfigRules": [_rule("a"), _rule("b")]}],
        compliance_pages=[{"ComplianceByConfigRules": [
            _compliance("a", "COMPLIANT"),
            _compliance("b", "INSUFFICIENT_DATA"),
        ]}],
    )
    result, *_ = _invoke({}, lambda_context, config)
    assert result["compliance_status"] == "PASS"
    body = json.loads(result["body"])
    assert body["insufficient_data_rules"] == ["b"]
    assert body["counts"]["insufficient_data"] == 1


def test_pagination_across_pages_is_counted(lambda_context):
    config = _config_client(
        rules_pages=[
            {"ConfigRules": [_rule("a"), _rule("b")]},
            {"ConfigRules": [_rule("c")]},
        ],
        compliance_pages=[
            {"ComplianceByConfigRules": [
                _compliance("a", "COMPLIANT"), _compliance("b", "COMPLIANT"),
            ]},
            {"ComplianceByConfigRules": [_compliance("c", "NON_COMPLIANT")]},
        ],
    )
    result, *_ = _invoke({}, lambda_context, config)
    body = json.loads(result["body"])
    assert body["rule_count"] == 3
    assert body["counts"]["compliant"] == 2
    assert body["counts"]["non_compliant"] == 1
    assert result["compliance_status"] == "FAIL"


def test_simulation_is_stamped_and_makes_no_api_calls(lambda_context):
    config = _config_client()
    result, config, *_ = _invoke({"mode": "simulation"}, lambda_context, config)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    assert config.calls == [], "simulation must not touch the Config API"
    # Deterministic demo drift: exactly one NON_COMPLIANT rule
    assert result["compliance_status"] == "FAIL"
    assert body["counts"]["non_compliant"] == 1


def test_evidence_written_to_bucket(lambda_context):
    result, _, s3, _, _ = _invoke({}, lambda_context)
    puts = s3.calls_to("put_object")
    assert puts and puts[0]["Bucket"] == "test-evidence-bucket"
    body = json.loads(result["body"])
    assert body["evidence_uri"].startswith("s3://test-evidence-bucket/")
    assert body["scf_controls"] == handler_mod.SCF_CONTROLS


def test_missing_bucket_is_config_error(lambda_context, monkeypatch):
    monkeypatch.delenv("EVIDENCE_BUCKET")
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_sdk_error_is_error_status(lambda_context):
    config = FakeClient(responses={"describe_configuration_recorder_status": RECORDING})
    # no pages configured → get_paginator raises → ERROR (never PASS)
    result, *_ = _invoke({}, lambda_context, config)
    assert result["compliance_status"] == "ERROR"


def test_asff_partition_from_context_arn_govcloud(govcloud_context):
    config = _config_client(
        compliance_pages=[{"ComplianceByConfigRules": [
            _compliance("restricted-ssh", "NON_COMPLIANT"),
        ]}],
    )
    result, _, _, _, securityhub = _invoke({}, govcloud_context, config)
    assert result["compliance_status"] == "FAIL"
    finding = securityhub.calls_to("batch_import_findings")[0]["Findings"][0]
    assert finding["ProductArn"].startswith("arn:aws-us-gov:securityhub:us-gov-west-1:")
    assert finding["AwsAccountId"] == "123456789012"
