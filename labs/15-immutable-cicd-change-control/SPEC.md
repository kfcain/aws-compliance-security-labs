# Specification — Immutable CI/CD Change Control & Deployment Validation

## Why this lab exists (federal data first)

Federal workloads must change through **reviewed, version-controlled redeploys**, not console mutation. Direct SG/IAM/CloudTrail changes create silent boundary and data-exposure risk.

CR26 Change Management:

| KSI | Outcome |
|-----|---------|
| `KSI-CMT-RMV` | Prefer redeploy of version-controlled resources over direct modify |
| `KSI-CMT-VTD` | Automate validation throughout deployment |
| `KSI-CMT-LMC` | Log and monitor CSO modifications |
| `KSI-CMT-RVP` | Persistently review change procedures |
| `KSI-AFR-SCN` | Classify significant changes (routine / adaptive / transformative) |

Underlying rules:

1. SCPs deny high-risk direct mutations for human principals in prod.
2. Pipeline is the only normal path to production; deploys reference immutable `commit_sha`.
3. Gates: IaC scan, policy-as-code, unit (+ integration) must pass; post-deploy validation required.
4. All change events logged; denylisted API calls by humans = FAIL.
5. SCN classification drives notification lead time.

## Functional requirements

1. Evaluate CloudTrail-like change events against forbidden direct-modify set.
2. Evaluate pipeline run gate matrix + post-deploy validation + commit binding.
3. Attach SCN classification metadata.
4. Emit procedure-review checklist evidence (`KSI-CMT-RVP`).

## Acceptance criteria

- [ ] Demo human `AuthorizeSecurityGroupIngress` FAILs
- [ ] Demo pipeline function update PASSes when via CodePipeline role
- [ ] Missing `policy_as_code` gate FAILs pipeline evaluation
- [ ] Evidence includes recommended SCP guardrails

## Test vectors

```bash
cd labs/15-immutable-cicd-change-control
python3 -c "from src.handler import handler; import json; print(json.loads(handler({}, None)['body'])['status'])"
python3 -c "from src.handler import handler; import json; r=handler({'pipeline_run':{'pipeline_name':'p','commit_sha':'x','gates':{'unit':True},'deployed':True,'post_deploy_validation':False,'change_class':'adaptive'}}, None); print(json.loads(r['body'])['status'])"
```

## Related labs

- **04** config intended state after deploy
- **07** CloudTrail is the change sensor
- **13** boundary resources must only change via this path
