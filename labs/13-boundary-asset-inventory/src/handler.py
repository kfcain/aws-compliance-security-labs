"""Authorization boundary + real-time asset inventory.

FedRAMP CR26 / overlays:
  KSI-PIY-GIV  authoritative real-time inventories
  KSI-AFR-MAS  minimum assessment scope / boundary (program overlay)
  KSI-CNA-DFP  define functionality and privileges
  KSI-MLA-LET  maintain logged resource/event-type inventory

Classifies every discovered resource as
``in_boundary | inherited | out_of_boundary (shadow) | unknown`` and requires
federal data stores to be in-boundary with owner + data-classification tags.

Boundary resolution (fail closed, never unioned):
  * ``event.boundary`` is authoritative when present — an event may *narrow*
    scope below the environment baseline.
  * ``ALLOWED_ACCOUNT_IDS`` env is a baseline used only when the event has no
    boundary. There is NO built-in default account list.
  * Neither present → ``CONFIG_ERROR`` — the control cannot attest scope
    without an authoritative boundary.

The lab's premise is a live inventory feed (Config Aggregator / Resource
Explorer). A missing or empty ``event.inventory`` outside simulation is
``CONFIG_ERROR``: an empty feed means the sensor is broken, not that the
estate is empty. Demo data enters only via ``{"mode": "simulation"}`` and is
stamped ``data_source: simulation``.

Evidence deliberately omits full resource tag maps — only the governance tags
that the classification logic reads (``REQUIRED_TAGS`` + ``boundary_status``)
are echoed, because arbitrary tags can carry sensitive operational metadata.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from lab_common import (
    ConfigError,
    EvidenceWriter,
    RuntimeContext,
    Status,
    coerce_bool,
    get_csv_env,
    get_logger,
    new_run_id,
    publish_alert,
    respond,
    simulation_requested,
    utc_now,
)

LAB_ID = "13-boundary-asset-inventory"
SCF_CONTROLS = ["AST-01", "AST-02", "AST-04", "NET-03", "CPL-01", "GOV-01"]
FEDRAMP_KSI = ["KSI-PIY-GIV", "KSI-AFR-MAS", "KSI-CNA-DFP", "KSI-MLA-LET"]

logger = get_logger(LAB_ID)

_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
_DEFAULT_REQUIRED_TAGS = [
    "federal_tenant_id",
    "data_classification",
    "boundary_status",
    "owner",
]


def _str_field(
    raw: dict[str, Any], key: str, where: str, *, required: bool = True, default: str = ""
) -> str:
    if key not in raw:
        if required:
            raise ValueError(f"{where}: missing required key {key!r}")
        return default
    value = raw[key]
    if not isinstance(value, str):
        raise ValueError(f"{where}: {key} must be a string, got {type(value).__name__}")
    return value


def _str_list_field(
    raw: dict[str, Any], key: str, where: str, *, required: bool = True
) -> list[str]:
    if key not in raw:
        if required:
            raise ValueError(f"{where}: missing required key {key!r}")
        return []
    value = raw[key]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(
            f"{where}: {key} must be a list of strings, got {type(value).__name__}"
        )
    return list(value)


def _validate_account_ids(values: list[str], where: str) -> list[str]:
    bad = [a for a in values if not _ACCOUNT_ID_RE.fullmatch(a)]
    if bad:
        raise ValueError(
            f"{where} must contain 12-digit AWS account id strings, got invalid entries {bad!r}"
        )
    return values


@dataclass
class BoundaryDefinition:
    system_name: str
    mas_version: str
    in_scope_account_ids: list[str]
    in_scope_services: list[str] = field(default_factory=list)
    inherited_providers: list[str] = field(default_factory=list)
    data_flow_summary: str = ""

    @classmethod
    def from_dict(cls, raw: Any) -> BoundaryDefinition:
        """Validated construction — never ``BoundaryDefinition(**raw)``.

        Unknown keys are ignored; wrong types raise ValueError with a clear
        message (a bare string for ``in_scope_account_ids`` previously became
        a silent set of characters via the ``**`` splat path).
        """
        if not isinstance(raw, dict):
            raise ValueError(f"boundary must be an object, got {type(raw).__name__}")
        where = "boundary"
        accounts = _validate_account_ids(
            _str_list_field(raw, "in_scope_account_ids", where),
            f"{where}: in_scope_account_ids",
        )
        return cls(
            system_name=_str_field(raw, "system_name", where),
            mas_version=_str_field(raw, "mas_version", where),
            in_scope_account_ids=accounts,
            in_scope_services=_str_list_field(raw, "in_scope_services", where, required=False),
            inherited_providers=_str_list_field(
                raw, "inherited_providers", where, required=False
            ),
            data_flow_summary=_str_field(raw, "data_flow_summary", where, required=False),
        )


@dataclass
class InventoryItem:
    resource_id: str
    resource_type: str
    account_id: str
    region: str
    tags: dict[str, str]
    processes_federal_data: bool = False

    @classmethod
    def from_dict(cls, raw: Any) -> InventoryItem:
        """Validated construction; unknown keys ignored, wrong types rejected."""
        if not isinstance(raw, dict):
            raise ValueError(f"inventory item must be an object, got {type(raw).__name__}")
        rid = raw.get("resource_id")
        if not isinstance(rid, str) or not rid:
            raise ValueError(
                "inventory item: resource_id must be a non-empty string, "
                f"got {type(rid).__name__}"
            )
        where = f"inventory item {rid!r}"
        account_raw = raw.get("account_id")
        if isinstance(account_raw, int) and not isinstance(account_raw, bool):
            account_id = f"{account_raw:012d}"
        elif isinstance(account_raw, str) and account_raw:
            account_id = account_raw
        else:
            raise ValueError(
                f"{where}: account_id must be a non-empty string (or int), "
                f"got {type(account_raw).__name__}"
            )
        tags_raw = raw.get("tags") or {}
        if not isinstance(tags_raw, dict):
            raise ValueError(f"{where}: tags must be an object, got {type(tags_raw).__name__}")
        pfd_raw = raw.get("processes_federal_data", False)
        pfd = coerce_bool(pfd_raw)
        if pfd is None:
            raise ValueError(
                f"{where}: processes_federal_data must be a boolean, got {pfd_raw!r}"
            )
        return cls(
            resource_id=rid,
            resource_type=_str_field(raw, "resource_type", where),
            account_id=account_id,
            region=_str_field(raw, "region", where, required=False, default="unknown"),
            tags={str(k): str(v) for k, v in tags_raw.items()},
            processes_federal_data=pfd,
        )


def classify(
    item: InventoryItem, boundary: BoundaryDefinition, required_tags: list[str]
) -> dict[str, Any]:
    issues: list[str] = []
    tag_boundary = item.tags.get("boundary_status", "").lower()
    in_scope = item.account_id in set(boundary.in_scope_account_ids)
    if not in_scope:
        classification = "out_of_boundary"
        issues.append("account not in MAS in-scope account list")
    elif tag_boundary == "inherited" or item.resource_type.startswith("AWS::Inherited::"):
        classification = "inherited"
    elif tag_boundary in ("", "in_boundary"):
        classification = "in_boundary"
    else:
        classification = "unknown"
        issues.append(
            f"boundary_status tag {tag_boundary!r} is unrecognized — ambiguous boundary mapping"
        )

    if item.processes_federal_data and classification == "out_of_boundary":
        issues.append("CRITICAL: federal data processed outside authorization boundary")

    missing_tags = [t for t in required_tags if not item.tags.get(t)]
    if item.processes_federal_data and missing_tags:
        issues.append(f"federal data resource missing tags: {', '.join(missing_tags)}")

    # Intended guard (the old `split("::")[0:2]` slice was always truthy):
    # only well-formed AWS::Service::Resource types are compared against the
    # MAS service catalog — free-form type strings are skipped.
    if (
        len(item.resource_type.split("::")) == 3
        and len(boundary.in_scope_services) > 0
        and item.resource_type not in boundary.in_scope_services
        and classification == "in_boundary"
        and item.processes_federal_data
    ):
        # soft warning — service not listed in MAS service catalog
        issues.append(f"resource type {item.resource_type} not listed in MAS service catalog")

    severity = "CRITICAL" if any("CRITICAL" in i for i in issues) else ("HIGH" if issues else "INFO")
    status = "FAIL" if issues else "PASS"
    # Only the governance tags the classification reads are echoed into
    # evidence — full tag maps can carry unrelated or sensitive operational
    # metadata and are deliberately omitted.
    governance_keys = list(dict.fromkeys([*required_tags, "boundary_status"]))
    return {
        "resource_id": item.resource_id,
        "resource_type": item.resource_type,
        "account_id": item.account_id,
        "region": item.region,
        "classification": classification,
        "processes_federal_data": item.processes_federal_data,
        "status": status,
        "severity": severity,
        "issues": issues,
        "governance_tags": {k: item.tags[k] for k in governance_keys if k in item.tags},
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


def _resolve_boundary(
    event: dict[str, Any], env_accounts: list[str], simulation: bool
) -> tuple[BoundaryDefinition, str]:
    """Boundary precedence: event > env baseline > simulation demo.

    The event boundary is authoritative — it is never unioned with the env
    baseline, so an event can narrow scope. No hardcoded default accounts.
    """
    braw = event.get("boundary")
    if braw is not None:
        return BoundaryDefinition.from_dict(braw), "event"
    if env_accounts:
        try:
            _validate_account_ids(env_accounts, "ALLOWED_ACCOUNT_IDS")
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        return (
            BoundaryDefinition(
                system_name="env-baseline",
                mas_version="env",
                in_scope_account_ids=env_accounts,
            ),
            "env",
        )
    if simulation:
        return demo_boundary(), "simulation"
    raise ConfigError(
        "no boundary definition: event has no `boundary` and ALLOWED_ACCOUNT_IDS is not set "
        "— cannot attest authorization scope without an authoritative boundary"
    )


def _resolve_inventory(
    event: dict[str, Any], simulation: bool
) -> tuple[list[InventoryItem], str]:
    items_raw = event.get("inventory")
    if items_raw is not None and not isinstance(items_raw, list):
        raise ValueError(f"inventory must be a list, got {type(items_raw).__name__}")
    if simulation:
        if items_raw:
            return [InventoryItem.from_dict(i) for i in items_raw], "simulation"
        return demo_inventory(), "simulation"
    if not items_raw:
        # Documented choice: this lab attests a live inventory feed. Zero
        # assets means the feed is broken/misrouted, so the safe verdict is
        # CONFIG_ERROR — never a PASS over demo data.
        raise ConfigError(
            "inventory feed is missing or empty — this lab attests a live inventory; "
            "an empty feed means the sensor is broken, not that the estate is empty"
        )
    return [InventoryItem.from_dict(i) for i in items_raw], "event"


def handler(
    event: dict[str, Any],
    context: Any,
    s3_client: Any = None,
    sns_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        RuntimeContext.from_lambda(context)  # fail closed if we can't tell where we run

        required_tags = get_csv_env("REQUIRED_TAGS", _DEFAULT_REQUIRED_TAGS)
        env_accounts = get_csv_env("ALLOWED_ACCOUNT_IDS", [])
        simulation = simulation_requested(event)

        boundary, boundary_source = _resolve_boundary(event, env_accounts, simulation)
        items, data_source = _resolve_inventory(event, simulation)

        classified = [classify(i, boundary, required_tags) for i in items]
        shadow = [c for c in classified if c["classification"] == "out_of_boundary"]
        federal_shadow = [c for c in shadow if c["processes_federal_data"]]
        failing = [c for c in classified if c["status"] == "FAIL"]
        status = Status.FAIL if failing else Status.PASS

        evidence = {
            "lab_id": LAB_ID,
            "checked_at": utc_now().isoformat(),
            "status": status.value,
            "data_source": data_source,
            "boundary_source": boundary_source,
            "boundary": asdict(boundary),
            "required_tags": required_tags,
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
        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is not Status.PASS:
            publish_alert(
                LAB_ID,
                status,
                f"{len(failing)} boundary violation(s); "
                f"{len(federal_shadow)} federal-data resource(s) outside boundary",
                sns_client=sns_client,
            )
        logger.info(
            "boundary inventory sweep complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "inventory": len(classified),
                "shadow": len(shadow),
                "federal_shadow": len(federal_shadow),
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
