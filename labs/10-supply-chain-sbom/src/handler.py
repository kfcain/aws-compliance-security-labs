"""Supply chain risk, SBOM & third-party monitoring validation.

Wire EventBridge (daily schedule) → this function → Security Hub / evidence
store. The lab attests the container supply-chain posture that SBOM/scan
evidence depends on:

  1. Inspector activation (KSI-SCR-SRA / KSI-AFR-VDR): Amazon Inspector v2
     account scanning must be ENABLED for ec2 and ecr (and lambda/lambdaCode
     when those resource states are present in the account status shape) —
     otherwise CVEs in images and hosts go undetected and no SBOM-backed
     vulnerability evidence exists.
  2. ECR registry hardening (KSI-SCR-TPM): every repository must scan on push
     (``imageScanningConfiguration.scanOnPush``) and pin provenance with
     ``imageTagMutability == "IMMUTABLE"`` (a mutable tag lets a compromised
     push silently replace a vetted image). KMS CMK encryption is preferred;
     AES256 is recorded as a warning, not a violation.

Event sources:
  * Scheduled sweep — Inspector2 BatchGetAccountStatus + paginated ECR
    DescribeRepositories
  * ``{"mode": "simulation"}`` — a fixed demo registry, stamped as simulated

Verdict semantics (fail closed):
  * CONFIG_ERROR — Inspector2 not activated in this account/region (the API
    answers AccessDenied before enablement); the control cannot be evaluated.
  * FAIL — Inspector scanning disabled for any governed resource, or any
    repository violating the registry floor. ASFF finding imported on FAIL.
  * PASS — Inspector fully enabled and every repository hardened. Zero
    repositories is noted (repos section NOT_APPLICABLE) but the Inspector
    account posture still governs the overall verdict.

Env contract: EVIDENCE_BUCKET, SNS_TOPIC_ARN, LOG_LEVEL.
"""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

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

LAB_ID = "10-supply-chain-sbom"
SCF_CONTROLS = ["TPM-01", "TPM-03", "TPM-04", "VPM-01", "AST-02"]
FEDRAMP_KSI = ["KSI-SCR-SRA", "KSI-SCR-TPM", "KSI-AFR-VDR"]

logger = get_logger(LAB_ID)

# Scanning must be on for these resource types in every account governed here.
REQUIRED_INSPECTOR_RESOURCES = ("ec2", "ecr")
# Checked only when the account-status shape reports them.
OPTIONAL_INSPECTOR_RESOURCES = ("lambda", "lambdaCode")
# Inspector2 answers AccessDenied before the service is activated — that is a
# configuration gap (enable Inspector), not an SDK failure.
_NOT_ACTIVATED_CODES = {"AccessDeniedException", "AccessDenied"}


# --------------------------------------------------------------------------
# Inspector account posture
# --------------------------------------------------------------------------

def fetch_inspector_accounts(inspector2_client: Any) -> list[dict[str, Any]]:
    try:
        response = inspector2_client.batch_get_account_status()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in _NOT_ACTIVATED_CODES:
            raise ConfigError(
                f"Inspector2 is not activated in this account/region ({code}) — "
                "enable Amazon Inspector before this control can be evaluated"
            ) from exc
        raise
    accounts = response.get("accounts", [])
    if not accounts:
        raise ConfigError(
            "Inspector2 returned no account status — scanning posture cannot be attested"
        )
    return accounts


def evaluate_inspector_accounts(
    accounts: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Per-account resource scan states + violations for anything not ENABLED."""
    results: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []

    def _check(account_id: str, resource: str, state: dict[str, Any]) -> str:
        scan_status = state.get("status", "MISSING")
        if scan_status != "ENABLED":
            violations.append({
                "type": "inspector_scanning_disabled",
                "account_id": account_id,
                "resource": resource,
                "scan_status": scan_status,
                "detail": (
                    f"Inspector scanning disabled for {resource} "
                    f"(status {scan_status}) in account {account_id}"
                ),
            })
        return scan_status

    for account in accounts:
        account_id = account.get("accountId", "unknown")
        resource_state = account.get("resourceState") or {}
        statuses: dict[str, str] = {}
        for resource in REQUIRED_INSPECTOR_RESOURCES:
            statuses[resource] = _check(account_id, resource, resource_state.get(resource) or {})
        for resource in OPTIONAL_INSPECTOR_RESOURCES:
            if resource in resource_state:
                statuses[resource] = _check(
                    account_id, resource, resource_state.get(resource) or {}
                )
        results.append({"account_id": account_id, "resource_scan_status": statuses})
    return results, violations


# --------------------------------------------------------------------------
# ECR registry hardening
# --------------------------------------------------------------------------

def list_repositories(ecr_client: Any) -> list[dict[str, Any]]:
    """Fully paginated — a truncated pull would understate the registry
    population under audit."""
    repositories: list[dict[str, Any]] = []
    for page in ecr_client.get_paginator("describe_repositories").paginate():
        repositories.extend(page.get("repositories", []))
    return repositories


def evaluate_repository(repo: dict[str, Any]) -> dict[str, Any]:
    name = repo.get("repositoryName", "unknown")
    violations: list[str] = []
    warnings: list[str] = []
    scan_on_push = bool((repo.get("imageScanningConfiguration") or {}).get("scanOnPush"))
    if not scan_on_push:
        violations.append(
            f"repository {name}: scanOnPush is disabled — images enter the registry unscanned"
        )
    mutability = repo.get("imageTagMutability", "")
    if mutability != "IMMUTABLE":
        violations.append(
            f"repository {name}: imageTagMutability is {mutability or 'unknown'} — "
            "IMMUTABLE is required so a vetted tag cannot be silently replaced"
        )
    encryption = (repo.get("encryptionConfiguration") or {}).get("encryptionType", "")
    if encryption != "KMS":
        # Documented posture preference, not a floor: AES256 still encrypts at
        # rest but forfeits CMK key policy / rotation / CloudTrail key usage.
        warnings.append(
            f"repository {name}: encryptionType is {encryption or 'unknown'} — "
            "KMS CMK preferred over AES256 for key-usage auditability"
        )
    return {
        "repository": name,
        "repository_arn": repo.get("repositoryArn", ""),
        "scan_on_push": scan_on_push,
        "image_tag_mutability": mutability,
        "encryption_type": encryption,
        "status": "FAIL" if violations else "PASS",
        "violations": violations,
        "warnings": warnings,
    }


def build_evidence(
    account_results: list[dict[str, Any]],
    inspector_violations: list[dict[str, Any]],
    repo_results: list[dict[str, Any]],
    data_source: str,
) -> dict[str, Any]:
    repo_violations = [
        {"type": "ecr_repository", "repository": r["repository"], "detail": detail}
        for r in repo_results
        for detail in r["violations"]
    ]
    warnings = [w for r in repo_results for w in r["warnings"]]
    violations = inspector_violations + repo_violations
    # Zero repositories: the repos section is NOT_APPLICABLE, but the
    # Inspector account posture still governs the overall verdict.
    if not repo_results:
        repos_status = Status.NOT_APPLICABLE.value
    elif repo_violations:
        repos_status = Status.FAIL.value
    else:
        repos_status = Status.PASS.value
    status = Status.FAIL if violations else Status.PASS
    return {
        "lab_id": LAB_ID,
        "checked_at": utc_now().isoformat(),
        "status": status.value,
        "data_source": data_source,
        "inspector_account_status": account_results,
        "inspector_violation_count": len(inspector_violations),
        "repositories": {
            "status": repos_status,
            "count": len(repo_results),
            "failing_count": sum(1 for r in repo_results if r["status"] == "FAIL"),
            "results": repo_results,
            "note": (
                "no ECR repositories in this account/region — Inspector account "
                "posture alone governs the verdict"
                if not repo_results
                else None
            ),
        },
        "violations": violations,
        "violation_count": len(violations),
        "warnings": warnings,
        "warning_count": len(warnings),
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "methodology": {
            "inspector": (
                "BatchGetAccountStatus — ec2/ecr (and lambda when reported) "
                "resource scanning must be ENABLED"
            ),
            "registry_floor": "per-repository scanOnPush=true and imageTagMutability=IMMUTABLE",
            "encryption": "KMS CMK preferred; AES256 recorded as a warning",
            "population": "describe_repositories, fully paginated",
            "persistent_cadence": "daily EventBridge schedule",
        },
    }


def _simulation_dataset() -> dict[str, Any]:
    """Small deterministic demo: Inspector enabled, one hardened repository
    and one soft repository (mutable tags, no scan-on-push) → deterministic FAIL."""
    return {
        "accounts": [
            {
                "accountId": "simulated-account",
                "resourceState": {
                    "ec2": {"status": "ENABLED"},
                    "ecr": {"status": "ENABLED"},
                },
            }
        ],
        "repositories": [
            {
                "repositoryName": "sim-hardened-api",
                "imageScanningConfiguration": {"scanOnPush": True},
                "imageTagMutability": "IMMUTABLE",
                "encryptionConfiguration": {"encryptionType": "KMS"},
            },
            {
                "repositoryName": "sim-legacy-worker",
                "imageScanningConfiguration": {"scanOnPush": False},
                "imageTagMutability": "MUTABLE",
                "encryptionConfiguration": {"encryptionType": "AES256"},
            },
        ],
    }


def handler(
    event: dict[str, Any],
    context: Any,
    inspector2_client: Any = None,
    ecr_client: Any = None,
    s3_client: Any = None,
    sns_client: Any = None,
    securityhub_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        runtime = RuntimeContext.from_lambda(context)  # fail closed if we can't tell where we run

        if simulation_requested(event):
            dataset = _simulation_dataset()
            accounts = dataset["accounts"]
            repositories = dataset["repositories"]
            data_source = "simulation"
        else:
            if inspector2_client is None:  # pragma: no cover - AWS only
                import boto3

                inspector2_client = boto3.client("inspector2")
            if ecr_client is None:  # pragma: no cover - AWS only
                import boto3

                ecr_client = boto3.client("ecr")
            accounts = fetch_inspector_accounts(inspector2_client)
            repositories = list_repositories(ecr_client)
            data_source = "aws-api"

        account_results, inspector_violations = evaluate_inspector_accounts(accounts)
        repo_results = [evaluate_repository(repo) for repo in repositories]
        evidence = build_evidence(
            account_results, inspector_violations, repo_results, data_source
        )
        status = Status(evidence["status"])

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is Status.FAIL:
            emitter = AsffEmitter(LAB_ID, runtime, client=securityhub_client)
            emitter.emit([emitter.build_finding(
                finding_id=f"supply-chain/{run_id}",
                title="Container supply-chain posture violations",
                description=(
                    f"{evidence['inspector_violation_count']} Inspector scanning "
                    f"gap(s) and {evidence['repositories']['failing_count']} of "
                    f"{evidence['repositories']['count']} ECR repositories failing "
                    "the registry floor. Fails KSI-SCR-SRA/TPM."
                ),
                severity="HIGH",
                resource_type="AwsEcrRepository",
                resource_id=f"account/{runtime.account_id}/container-supply-chain",
                status=status,
            )])
        if status is not Status.PASS:
            publish_alert(
                LAB_ID,
                status,
                f"{evidence['violation_count']} supply-chain violation(s): "
                f"{evidence['inspector_violation_count']} Inspector scanning gap(s), "
                f"{evidence['repositories']['failing_count']} of "
                f"{evidence['repositories']['count']} repositories failing",
                sns_client=sns_client,
            )
        logger.info(
            "supply-chain posture sweep complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "repositories": evidence["repositories"]["count"],
                "violations": evidence["violation_count"],
                "warnings": evidence["warning_count"],
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
        return respond(Status.ERROR, {"lab_ID": LAB_ID, "error": str(exc), "run_id": run_id})
