"""
Authorization boundary + real-time asset inventory.

FedRAMP CR26 / overlays:
  KSI-PIY-GIV  authoritative real-time inventories
  KSI-AFR-MAS  minimum assessment scope / boundary (program overlay)
  KSI-CNA-DFP  define functionality and privileges
  KSI-MLA-LET  maintain logged resource/event-type inventory

Classifies every discovered resource as:
  in_boundary | inherited | out_of_boundary (shadow) | unknown
and requires federal data stores to be in_boundary with owner + data class tags.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

LAB_ID = "13-boundary-asset-inventory"
SCF_CONTROLS = ["AST-01", "AST-02", "AST-04", "NET-03", "CPL-01", "GOV-01"]
FEDRAMP_KSI = ["KSI-PIY-GIV", "KSI-AFR-MAS", "KSI-CNA-DFP", "KSI-MLA-LET"]

REQUIRED_TAGS = [
    t.strip()
    for t in os.environ.get(
        "REQUIRED_TAGS", "federal_tenant_id,data_classification,boundary_status,owner"
    ).split(",")
    if t.strip()
]
ALLOWED_ACCOUNTS = {
    a.strip()
    for a in os.environ.get("ALLOWED_ACCOUNT_IDS", "111111111111,222222222222").split(",")
    if a.strip()
}


@dataclass
class BoundaryDefinition:
    system_name: str
    mas_version: str
    in_scope_account_ids: list[str]
    in_scope_services: list[str]
    inherited_providers: list[str] = field(default_factory=list)
    data_flow_summary: str = ""


@dataclass
class InventoryItem:
    resource_id: str
    resource_type: str
    account_id: str
    region: str
    tags: dict[str, str]
    processes_federal_data: bool = False


def classify(item: InventoryItem, boundary: BoundaryDefinition) -> dict[str, Any]:
    issues: list[str] = []
    tag_boundary = item.tags.get("boundary_status", "").lower()
    if item.account_id not in set(boundary.in_scope_account_ids) | ALLOWED_ACCOUNTS:
        classification = "out_of_boundary"
        issues.append("account not in MAS / allowed account list")
    elif tag_boundary == "inherited" or item.resource_type.startswith("AWS::Inherited::"):
        classification = "inherited"
    elif tag_boundary == "in_boundary" or item.account_id in boundary.in_scope_account_ids:
        classification = "in_boundary"
    else:
        classification = "unknown"
        issues.append("missing boundary_status tag and ambiguous account mapping")

    if item.processes_federal_data and classification == "out_of_boundary":
        issues.append("CRITICAL: federal data processed outside authorization boundary")

    missing_tags = [t for t in REQUIRED_TAGS if t not in item.tags or not item.tags[t]]
    if item.processes_federal_data and missing_tags:
        issues.append(f"federal data resource missing tags: {', '.join(missing_tags)}")

    if (
        item.resource_type.split("::")[0:2]
        and len(boundary.in_scope_services) > 0
        and item.resource_type not in boundary.in_scope_services
        and classification == "in_boundary"
        and item.processes_federal_data
    ):
        # soft warning — service not listed in MAS service catalog
        issues.append(f"resource type {item.resource_type} not listed in MAS service catalog")

    severity = "CRITICAL" if any("CRITICAL" in i for i in issues) else ("HIGH" if issues else "INFO")
    status = "FAIL" if issues else "PASS"
    return {
        "resource_id": item.resource_id,
        "resource_type": item.resource_type,
        "account_id": item.account_id,
        "classification": classification,
        "processes_federal_data": item.processes_federal_data,
        "status": status,
        "severity": severity,
        "issues": issues,
        "tags": item.tags,
    }


def demo_boundary() -> BoundaryDefinition:
    return BoundaryDefinition(
        system_name="Federal SaaS CSO",
        mas_version="2026.1",
        in_scope_account_ids=["111111111111", "222222222222"],
        in_scope_services=[
            "AWS::S3::Bucket",
            "AWS::DynamoDB::Table",
            "AWS::RDS::DBInstance",
            "AWS::Lambda::Function",
            "AWS::ElasticLoadBalancingV2::LoadBalancer",
        ],
        inherited_providers=["AWS GovCloud (FedRAMP High)"],
        data_flow_summary="Agency user → ALB → App Lambda → DynamoDB/S3 (CUI)",
    )


def demo_inventory() -> list[InventoryItem]:
    return [
        InventoryItem(
            "arn:aws:s3:::cso-tenant-data",
            "AWS::S3::Bucket",
            "111111111111",
            "us-gov-west-1",
            {
                "boundary_status": "in_boundary",
                "federal_tenant_id": "agency-a",
                "data_classification": "CUI",
                "owner": "platform-team",
            },
            True,
        ),
        InventoryItem(
            "arn:aws:s3:::shadow-analytics",
            "AWS::S3::Bucket",
            "999999999999",
            "us-east-1",
            {"owner": "data-science"},
            True,
        ),
        InventoryItem(
            "arn:aws:kms:us-gov-west-1:111111111111:key/abc",
            "AWS::KMS::Key",
            "111111111111",
            "us-gov-west-1",
            {
                "boundary_status": "in_boundary",
                "federal_tenant_id": "shared",
                "data_classification": "CUI",
                "owner": "security",
            },
            False,
        ),
    ]


def build_event_type_inventory() -> list[dict[str, str]]:
    """KSI-MLA-LET companion list — what must be logged for in-boundary resources."""
    return [
        {"resource_class": "auth", "event_types": "ConsoleLogin,AssumeRole,CredentialExchange"},
        {"resource_class": "data_plane", "event_types": "S3 Object access, DynamoDB data events (selective)"},
        {"resource_class": "control_plane", "event_types": "CloudTrail management events (all regions)"},
        {"resource_class": "security", "event_types": "GuardDuty findings, Security Hub, Config compliance"},
    ]


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    braw = event.get("boundary") or {}
    boundary = (
        BoundaryDefinition(**braw)
        if braw
        else demo_boundary()
    )
    items_raw = event.get("inventory")
    items = (
        [
            InventoryItem(
                resource_id=i["resource_id"],
                resource_type=i["resource_type"],
                account_id=str(i["account_id"]),
                region=i.get("region", "unknown"),
                tags=dict(i.get("tags") or {}),
                processes_federal_data=bool(i.get("processes_federal_data", False)),
            )
            for i in items_raw
        ]
        if items_raw
        else demo_inventory()
    )

    classified = [classify(i, boundary) for i in items]
    shadow = [c for c in classified if c["classification"] == "out_of_boundary"]
    federal_shadow = [c for c in shadow if c["processes_federal_data"]]
    failing = [c for c in classified if c["status"] == "FAIL"]

    evidence = {
        "lab_id": LAB_ID,
        "checked_at": datetime.now(UTC).isoformat(),
        "status": "FAIL" if failing else "PASS",
        "boundary": asdict(boundary),
        "inventory_count": len(classified),
        "counts_by_classification": {
            key: sum(1 for c in classified if c["classification"] == key)
            for key in ["in_boundary", "inherited", "out_of_boundary", "unknown"]
        },
        "shadow_resources": shadow,
        "federal_data_outside_boundary": federal_shadow,
        "failing": failing,
        "results": classified,
        "logging_event_type_inventory": build_event_type_inventory(),
        "data_flow": {
            "summary": boundary.data_flow_summary,
            "rule": "Every federal data store in the flow must classify in_boundary with required tags.",
        },
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
    }
    print(
        json.dumps(
            {
                "status": evidence["status"],
                "shadow": len(shadow),
                "federal_shadow": len(federal_shadow),
            }
        )
    )
    return {"statusCode": 200, "body": json.dumps(evidence)}
