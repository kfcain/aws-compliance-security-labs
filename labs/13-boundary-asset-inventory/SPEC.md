# Specification — Authorization Boundary & Real-Time Asset Inventory

## Why this lab exists (federal data first)

You cannot encrypt, monitor, delete, or recover federal data that is **outside the known authorization boundary**. FedRAMP Minimum Assessment Scope practice and CR26 `KSI-PIY-GIV` require authoritative, automatable inventories.

Underlying rules:

1. Publish a **MAS / boundary definition**: in-scope accounts, services, inherited providers, data-flow summary.
2. Continuously discover resources (Config Aggregator / Resource Explorer).
3. Classify: `in_boundary` | `inherited` | `out_of_boundary` | `unknown`.
4. Any resource that `processes_federal_data` and is `out_of_boundary` is **CRITICAL**.
5. Federal data resources must carry required tags (`federal_tenant_id`, `data_classification`, `boundary_status`, `owner`).
6. Maintain a companion **logging event-type inventory** (`KSI-MLA-LET`).

## Goal

Persistently prove inventory completeness and boundary hygiene.

## Functional requirements

1. Load boundary definition (versioned MAS).
2. Normalize inventory items from Config/Explorer (lab accepts JSON inventory).
3. Classify + collect shadow/federal-shadow sets.
4. Emit FAIL if any classification issues; attach event-type inventory.

## Acceptance criteria

- [ ] Demo inventory flags `shadow-analytics` as federal data outside boundary
- [ ] In-boundary tagged CUI bucket PASSes
- [ ] Evidence includes `counts_by_classification` and `logging_event_type_inventory`
- [ ] Diagram + SCF mapping present

## Test vectors

```bash
cd labs/13-boundary-asset-inventory
python3 -c "from src.handler import handler; import json; b=json.loads(handler({}, None)['body']); print(b['status'], len(b['federal_data_outside_boundary']))"
```

## Related labs

- Feeds **11** deletion catalog
- Feeds **04** config scope
- Feeds **07** which accounts must have org trails
