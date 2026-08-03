"""Behavior tests for lab 08 (VPC segmentation & flow visibility)."""
from __future__ import annotations

import json

from conftest import FakeClient, load_lab_module

handler_mod = load_lab_module("08-vpc-network-segmentation")


def _ec2(vpcs=None, flow_logs=None, security_groups=None):
    return FakeClient(pages={
        "describe_vpcs": [{"Vpcs": vpcs or []}],
        "describe_flow_logs": [{"FlowLogs": flow_logs or []}],
        "describe_security_groups": [{"SecurityGroups": security_groups or []}],
    })


def _invoke(event, lambda_context, ec2=None):
    ec2 = ec2 or _ec2()
    s3, sns, hub = FakeClient(), FakeClient(), FakeClient(
        responses={"batch_import_findings": {"SuccessCount": 1}})
    result = handler_mod.handler(
        event, lambda_context,
        ec2_client=ec2, s3_client=s3, sns_client=sns, securityhub_client=hub,
    )
    return result, ec2, s3, sns, hub


def test_vpc_without_flow_log_fails(lambda_context):
    ec2 = _ec2(
        vpcs=[{"VpcId": "vpc-a"}, {"VpcId": "vpc-b"}],
        flow_logs=[{"ResourceId": "vpc-a", "FlowLogStatus": "ACTIVE"}],
    )
    result, _, _, sns, hub = _invoke({}, lambda_context, ec2)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert body["flow_log_coverage_percent"] == 50.0
    assert [v["vpc_id"] for v in body["flow_log_violations"]] == ["vpc-b"]
    assert hub.calls_to("batch_import_findings") and sns.calls_to("publish")


def test_inactive_flow_log_does_not_count(lambda_context):
    ec2 = _ec2(
        vpcs=[{"VpcId": "vpc-a"}],
        flow_logs=[{"ResourceId": "vpc-a", "FlowLogStatus": "INACTIVE"}],
    )
    result, *_ = _invoke({}, lambda_context, ec2)
    assert result["compliance_status"] == "FAIL"


def test_world_open_ssh_fails(lambda_context):
    ec2 = _ec2(
        vpcs=[{"VpcId": "vpc-a"}],
        flow_logs=[{"ResourceId": "vpc-a", "FlowLogStatus": "ACTIVE"}],
        security_groups=[{
            "GroupId": "sg-1", "GroupName": "bad",
            "IpPermissions": [{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        }],
    )
    result, *_ = _invoke({}, lambda_context, ec2)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert body["security_group_violations"][0]["security_group_id"] == "sg-1"


def test_world_open_https_alone_passes(lambda_context):
    """Only 22/3389/all-traffic are violations — public 443 is normal."""
    ec2 = _ec2(
        vpcs=[{"VpcId": "vpc-a"}],
        flow_logs=[{"ResourceId": "vpc-a", "FlowLogStatus": "ACTIVE"}],
        security_groups=[{
            "GroupId": "sg-web", "GroupName": "web",
            "IpPermissions": [{
                "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        }],
    )
    result, *_ = _invoke({}, lambda_context, ec2)
    assert result["compliance_status"] == "PASS"


def test_all_traffic_world_open_fails(lambda_context):
    ec2 = _ec2(
        vpcs=[{"VpcId": "vpc-a"}],
        flow_logs=[{"ResourceId": "vpc-a", "FlowLogStatus": "ACTIVE"}],
        security_groups=[{
            "GroupId": "sg-all", "GroupName": "wide",
            "IpPermissions": [{
                "IpProtocol": "-1",
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }],
        }],
    )
    result, *_ = _invoke({}, lambda_context, ec2)
    assert result["compliance_status"] == "FAIL"


def test_zero_vpcs_not_applicable(lambda_context):
    result, *_ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "NOT_APPLICABLE"


def test_pagination_across_pages(lambda_context):
    ec2 = FakeClient(pages={
        "describe_vpcs": [{"Vpcs": [{"VpcId": "vpc-a"}]}, {"Vpcs": [{"VpcId": "vpc-b"}]}],
        "describe_flow_logs": [
            {"FlowLogs": [{"ResourceId": "vpc-a", "FlowLogStatus": "ACTIVE"}]},
            {"FlowLogs": [{"ResourceId": "vpc-b", "FlowLogStatus": "ACTIVE"}]},
        ],
        "describe_security_groups": [{"SecurityGroups": []}],
    })
    result, *_ = _invoke({}, lambda_context, ec2)
    body = json.loads(result["body"])
    assert body["vpc_count"] == 2
    assert result["compliance_status"] == "PASS"


def test_simulation_is_stamped(lambda_context):
    result, *_ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"


def test_sdk_error_is_error_status(lambda_context):
    result, *_ = _invoke({}, lambda_context, FakeClient())  # no pages configured
    assert result["compliance_status"] == "ERROR"


def test_evidence_written(lambda_context):
    result, _, s3, *_ = _invoke({"mode": "simulation"}, lambda_context)
    assert s3.calls_to("put_object")
