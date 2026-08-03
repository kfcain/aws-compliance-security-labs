"""VPC network segmentation & flow-log visibility validation.

Wire EventBridge (daily schedule) → this function → Security Hub / evidence
store. Two control objectives, both evaluated from live EC2 API reads:

  1. Flow visibility (KSI-MLA-style monitoring for the network layer): every
     VPC must have at least one flow log in ``FlowLogStatus == "ACTIVE"``.
     Coverage percent is computed over the full, paginated VPC population.
  2. Segmentation floor (KSI-CNA-RNT/MAT): no security group may allow
     world-open ingress (0.0.0.0/0 or ::/0) to the sensitive admin ports
     (22/SSH, 3389/RDP) or via an all-traffic (``IpProtocol == "-1"``) rule.
     World-open ingress on other ports (e.g. 443 on a public ALB) is normal
     and is NOT a violation of this control.

Event sources:
  * Scheduled sweep — VPCs, flow logs, and security groups are pulled from
    the EC2 API (all three fully paginated)
  * ``{"mode": "simulation"}`` — a fixed demo network, stamped as simulated

Verdict semantics (fail closed):
  * NOT_APPLICABLE — zero VPCs in the account/region; nothing to segment.
  * FAIL — any VPC without an active flow log, or any world-open sensitive
    ingress rule. An ASFF finding is imported on FAIL.
  * PASS — 100% flow-log coverage and no world-open sensitive ingress.

Env contract: EVIDENCE_BUCKET, SNS_TOPIC_ARN, LOG_LEVEL.
"""
from __future__ import annotations

from typing import Any

from lab_common import (
    AsffEmitter,
    ConfigError,
    EvidenceWriter,
    RuntimeContext,
    Status,
    get_logger,
    new_run_id,
    publish_alert,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "08-vpc-network-segmentation"
SCF_CONTROLS = ["NET-01", "NET-04", "AST-04", "CLD-06"]
FEDRAMP_KSI = ["KSI-CNA-RNT", "KSI-CNA-MAT", "KSI-SVC-SNT"]

logger = get_logger(LAB_ID)

# Admin/management ports that must never be world-open. 443 et al. are
# legitimately public on edge load balancers and are out of scope here.
SENSITIVE_PORTS = {22: "SSH", 3389: "RDP"}
WORLD_IPV4 = "0.0.0.0/0"  # noqa: S104 - CIDR literal under test, not a bind address
WORLD_IPV6 = "::/0"


# --------------------------------------------------------------------------
# EC2 reads — fully paginated; a truncated pull would understate the
# population under audit
# --------------------------------------------------------------------------

def list_vpcs(ec2_client: Any) -> list[dict[str, Any]]:
    vpcs: list[dict[str, Any]] = []
    for page in ec2_client.get_paginator("describe_vpcs").paginate():
        vpcs.extend(page.get("Vpcs", []))
    return vpcs


def active_flow_logs_by_resource(ec2_client: Any) -> dict[str, dict[str, Any]]:
    """Map ResourceId → flow log, keeping only ACTIVE flow logs. A flow log
    that exists but is not ACTIVE provides no visibility and does not count."""
    mapping: dict[str, dict[str, Any]] = {}
    for page in ec2_client.get_paginator("describe_flow_logs").paginate():
        for flow_log in page.get("FlowLogs", []):
            if flow_log.get("FlowLogStatus") == "ACTIVE":
                mapping[flow_log.get("ResourceId", "")] = flow_log
    return mapping


def list_security_groups(ec2_client: Any) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    for page in ec2_client.get_paginator("describe_security_groups").paginate():
        groups.extend(page.get("SecurityGroups", []))
    return groups


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

def evaluate_flow_coverage(
    vpcs: list[dict[str, Any]], active_flow_logs: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    results = []
    for vpc in vpcs:
        vpc_id = vpc.get("VpcId", "unknown")
        flow_log = active_flow_logs.get(vpc_id)
        results.append({
            "vpc_id": vpc_id,
            "cidr_block": vpc.get("CidrBlock", ""),
            "is_default": bool(vpc.get("IsDefault", False)),
            "flow_log_active": flow_log is not None,
            "flow_log_id": (flow_log or {}).get("FlowLogId"),
            "log_destination_type": (flow_log or {}).get("LogDestinationType"),
        })
    return results


def _world_open_sources(rule: dict[str, Any]) -> list[str]:
    sources = [
        r.get("CidrIp", "")
        for r in rule.get("IpRanges", [])
        if r.get("CidrIp") == WORLD_IPV4
    ]
    sources += [
        r.get("CidrIpv6", "")
        for r in rule.get("Ipv6Ranges", [])
        if r.get("CidrIpv6") == WORLD_IPV6
    ]
    return sources


def _exposed_sensitive_ports(rule: dict[str, Any]) -> tuple[list[int], bool]:
    """Sensitive ports this rule exposes, plus whether it is all-traffic.

    ``IpProtocol == "-1"`` means every protocol/port. A tcp/udp rule with no
    port qualifier covers every port of that protocol and is treated the same
    (fail closed). Otherwise the FromPort..ToPort range is checked for 22/3389.
    """
    if rule.get("IpProtocol") == "-1":
        return sorted(SENSITIVE_PORTS), True
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort", from_port)
    if from_port is None:
        return sorted(SENSITIVE_PORTS), False
    return [p for p in sorted(SENSITIVE_PORTS) if from_port <= p <= to_port], False


def evaluate_security_groups(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One violation per (security group, offending ingress rule)."""
    violations: list[dict[str, Any]] = []
    for group in groups:
        for rule in group.get("IpPermissions", []):
            sources = _world_open_sources(rule)
            if not sources:
                continue
            ports, all_traffic = _exposed_sensitive_ports(rule)
            if not ports:
                continue  # world-open on non-sensitive ports (e.g. 443) is allowed
            exposure = (
                "all traffic"
                if all_traffic
                else f"ports {rule.get('FromPort')}-{rule.get('ToPort')}"
            )
            named = ", ".join(f"{p}/{SENSITIVE_PORTS[p]}" for p in ports)
            violations.append({
                "type": "world_open_sensitive_ingress",
                "security_group_id": group.get("GroupId", "unknown"),
                "group_name": group.get("GroupName", ""),
                "vpc_id": group.get("VpcId", ""),
                "ip_protocol": rule.get("IpProtocol"),
                "from_port": rule.get("FromPort"),
                "to_port": rule.get("ToPort"),
                "sensitive_ports_exposed": ports,
                "all_traffic": all_traffic,
                "world_open_sources": sources,
                "detail": (
                    f"security group {group.get('GroupId', 'unknown')} allows "
                    f"{'/'.join(sources)} ingress on {exposure} exposing {named}"
                ),
            })
    return violations


def build_evidence(
    vpc_results: list[dict[str, Any]],
    sg_violations: list[dict[str, Any]],
    security_group_count: int,
    data_source: str,
) -> dict[str, Any]:
    flow_violations = [
        {
            "type": "no_flow_visibility",
            "vpc_id": r["vpc_id"],
            "detail": f"VPC {r['vpc_id']} has no ACTIVE flow log — no flow visibility",
        }
        for r in vpc_results
        if not r["flow_log_active"]
    ]
    covered = len(vpc_results) - len(flow_violations)
    if not vpc_results:
        status = Status.NOT_APPLICABLE
        coverage = None
    elif flow_violations or sg_violations:
        status = Status.FAIL
        coverage = round(100.0 * covered / len(vpc_results), 1)
    else:
        status = Status.PASS
        coverage = round(100.0 * covered / len(vpc_results), 1)
    return {
        "lab_id": LAB_ID,
        "checked_at": utc_now().isoformat(),
        "status": status.value,
        "data_source": data_source,
        "vpc_count": len(vpc_results),
        "vpcs_with_active_flow_logs": covered,
        "flow_log_coverage_percent": coverage,
        "vpcs": vpc_results,
        "security_group_count": security_group_count,
        "flow_log_violations": flow_violations,
        "security_group_violations": sg_violations,
        "violation_count": len(flow_violations) + len(sg_violations),
        "note": (
            "no VPCs in this account/region — nothing to segment"
            if not vpc_results
            else None
        ),
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "methodology": {
            "flow_visibility": "every VPC requires a flow log with FlowLogStatus ACTIVE",
            "segmentation_floor": (
                "no world-open (0.0.0.0/0 or ::/0) ingress to ports 22/3389 "
                "or via all-traffic rules; other world-open ports are out of scope"
            ),
            "population": "describe_vpcs / describe_flow_logs / describe_security_groups, fully paginated",
            "persistent_cadence": "daily EventBridge schedule",
        },
    }


def _simulation_dataset() -> dict[str, Any]:
    """Small deterministic demo network: one covered VPC, one without flow
    visibility, and one world-open SSH rule → deterministic FAIL."""
    return {
        "vpcs": [
            {"VpcId": "vpc-sim-app", "CidrBlock": "10.10.0.0/16"},
            {"VpcId": "vpc-sim-data", "CidrBlock": "10.20.0.0/16"},
        ],
        "flow_logs": [
            {
                "FlowLogId": "fl-sim-1",
                "ResourceId": "vpc-sim-app",
                "FlowLogStatus": "ACTIVE",
                "LogDestinationType": "s3",
            },
        ],
        "security_groups": [
            {
                "GroupId": "sg-sim-bastion",
                "GroupName": "sim-bastion",
                "VpcId": "vpc-sim-app",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": WORLD_IPV4}],
                        "Ipv6Ranges": [],
                    }
                ],
            },
        ],
    }


def handler(
    event: dict[str, Any],
    context: Any,
    ec2_client: Any = None,
    s3_client: Any = None,
    sns_client: Any = None,
    securityhub_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        runtime = RuntimeContext.from_lambda(context)  # fail closed if we can't tell where we run

        if simulation_requested(event):
            dataset = _simulation_dataset()
            vpcs = dataset["vpcs"]
            active_flow_logs = {
                fl["ResourceId"]: fl
                for fl in dataset["flow_logs"]
                if fl.get("FlowLogStatus") == "ACTIVE"
            }
            groups = dataset["security_groups"]
            data_source = "simulation"
        else:
            if ec2_client is None:  # pragma: no cover - AWS only
                import boto3

                ec2_client = boto3.client("ec2")
            vpcs = list_vpcs(ec2_client)
            if vpcs:
                active_flow_logs = active_flow_logs_by_resource(ec2_client)
                groups = list_security_groups(ec2_client)
            else:  # nothing to segment — skip the remaining reads
                active_flow_logs, groups = {}, []
            data_source = "ec2-api"

        vpc_results = evaluate_flow_coverage(vpcs, active_flow_logs)
        sg_violations = evaluate_security_groups(groups)
        evidence = build_evidence(vpc_results, sg_violations, len(groups), data_source)
        status = Status(evidence["status"])

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is Status.FAIL:
            emitter = AsffEmitter(LAB_ID, runtime, client=securityhub_client)
            emitter.emit([emitter.build_finding(
                finding_id=f"segmentation/{run_id}",
                title="VPC segmentation / flow visibility violations",
                description=(
                    f"{len(evidence['flow_log_violations'])} VPC(s) without an active "
                    f"flow log and {len(sg_violations)} world-open sensitive ingress "
                    f"rule(s) across {evidence['vpc_count']} VPC(s). "
                    "Fails KSI-CNA-RNT/MAT segmentation floor."
                ),
                severity="HIGH",
                resource_type="AwsEc2Vpc",
                resource_id=f"account/{runtime.account_id}/vpc-segmentation",
                status=status,
            )])
        if status is not Status.PASS:
            publish_alert(
                LAB_ID,
                status,
                f"{evidence['violation_count']} network violation(s): "
                f"flow-log coverage {evidence['flow_log_coverage_percent']}% over "
                f"{evidence['vpc_count']} VPC(s), "
                f"{len(sg_violations)} world-open sensitive ingress rule(s)",
                sns_client=sns_client,
            )
        logger.info(
            "network segmentation sweep complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "vpcs": evidence["vpc_count"],
                "coverage_percent": evidence["flow_log_coverage_percent"],
                "violations": evidence["violation_count"],
            }},
        )
        return respond(status, evidence)
    except ConfigError as exc:
        logger.error(
            "configuration error",
            extra={"extra_fields": {"run_id": run_id, "error": str(exc)}},
        )
        return respond(Status.CONFIG_ERROR, {"lab_id": LAB_ID, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001 - fail closed, never crash the invocation
        logger.exception("unhandled error")
        return respond(Status.ERROR, {"lab_id": LAB_ID, "error": str(exc), "run_id": run_id})
