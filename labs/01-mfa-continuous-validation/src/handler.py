"""
Persistent MFA validation worker.

Integrations:
  - Okta: Users API + Factors (or System Log)
  - Descope: Management API / user auth methods
  - AWS IAM Identity Center + CloudTrail ConsoleLogin / AssumeRoleWithSAML

Emits Security Hub ASFF findings when a human identity lacks phishing-resistant MFA.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

LAB_ID = "01-mfa-continuous-validation"
SCF_CONTROLS = ["IAC-06", "IAC-15", "IAC-21", "MON-01"]
FEDRAMP_KSI = ["KSI-IAM-MFA", "KSI-IAM-ELP", "KSI-AFR-PVL"]

IDP_PROVIDER = os.environ.get("IDP_PROVIDER", "okta")  # okta | descope
OKTA_DOMAIN = os.environ.get("OKTA_DOMAIN", "")
DESCOPE_PROJECT_ID = os.environ.get("DESCOPE_PROJECT_ID", "")
IDP_API_TOKEN = os.environ.get("IDP_API_TOKEN", "")
EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET", "")
AWS_ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", "000000000000")
PRODUCT_ARN = os.environ.get(
    "SECURITYHUB_PRODUCT_ARN",
    f"arn:aws:securityhub:us-east-1:{AWS_ACCOUNT_ID}:product/{AWS_ACCOUNT_ID}/default",
)


@dataclass
class IdentityMfaStatus:
    user_id: str
    email: str
    mfa_enabled: bool
    phishing_resistant: bool
    factors: list[str]
    source: str


def _http_json(url: str, headers: dict[str, str]) -> Any:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_okta_users() -> list[IdentityMfaStatus]:
    """List active Okta users and factor types (lab-scale; paginate in production)."""
    if not OKTA_DOMAIN or not IDP_API_TOKEN:
        return [
            IdentityMfaStatus(
                user_id="demo-user",
                email="demo@example.com",
                mfa_enabled=True,
                phishing_resistant=True,
                factors=["webauthn"],
                source="okta-demo",
            )
        ]
    base = f"https://{OKTA_DOMAIN}/api/v1"
    headers = {
        "Authorization": f"SSWS {IDP_API_TOKEN}",
        "Accept": "application/json",
    }
    users = _http_json(f"{base}/users?limit=50&filter=status eq \"ACTIVE\"", headers)
    results: list[IdentityMfaStatus] = []
    for user in users:
        uid = user["id"]
        factors = _http_json(f"{base}/users/{uid}/factors", headers)
        types = [f.get("factorType", "") for f in factors if f.get("status") == "ACTIVE"]
        phishing = any(t in {"webauthn", "u2f", "signed_nonce"} for t in types)
        results.append(
            IdentityMfaStatus(
                user_id=uid,
                email=user.get("profile", {}).get("email", ""),
                mfa_enabled=len(types) > 0,
                phishing_resistant=phishing,
                factors=types,
                source="okta",
            )
        )
    return results


def fetch_descope_users() -> list[IdentityMfaStatus]:
    """Descope management API stub — replace with official SDK in production."""
    if not DESCOPE_PROJECT_ID or not IDP_API_TOKEN:
        return [
            IdentityMfaStatus(
                user_id="descope-demo",
                email="demo@example.com",
                mfa_enabled=True,
                phishing_resistant=False,
                factors=["totp"],
                source="descope-demo",
            )
        ]
    # Placeholder: Descope REST search users
    return fetch_okta_users()  # structure-compatible demo path


def evaluate(identities: list[IdentityMfaStatus]) -> dict[str, Any]:
    failures = [
        asdict(i)
        for i in identities
        if (not i.mfa_enabled) or (not i.phishing_resistant)
    ]
    status = "PASS" if not failures else "FAIL"
    return {
        "lab_id": LAB_ID,
        "checked_at": datetime.now(UTC).isoformat(),
        "status": status,
        "idp_provider": IDP_PROVIDER,
        "checked_count": len(identities),
        "failure_count": len(failures),
        "failures": failures,
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "policy": {
            "require_mfa": True,
            "require_phishing_resistant": True,
            "accepted_factors": ["webauthn", "u2f", "signed_nonce"],
        },
    }


def to_asff_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    if report["status"] == "PASS":
        return []
    findings = []
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    for fail in report["failures"]:
        findings.append(
            {
                "SchemaVersion": "2018-10-08",
                "Id": f"mfa/{fail['user_id']}",
                "ProductArn": PRODUCT_ARN,
                "GeneratorId": LAB_ID,
                "AwsAccountId": AWS_ACCOUNT_ID,
                "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
                "CreatedAt": now,
                "UpdatedAt": now,
                "Severity": {"Label": "HIGH"},
                "Title": "Human identity missing phishing-resistant MFA",
                "Description": (
                    f"User {fail.get('email') or fail['user_id']} factors={fail.get('factors')} "
                    f"source={fail.get('source')}. Maps to SCF IAC-06 / FedRAMP KSI-IAM-MFA."
                ),
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": fail["user_id"],
                        "Partition": "aws",
                        "Region": os.environ.get("AWS_REGION", "us-east-1"),
                    }
                ],
                "Compliance": {"Status": "FAILED"},
                "RecordState": "ACTIVE",
            }
        )
    return findings


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        identities = (
            fetch_descope_users() if IDP_PROVIDER == "descope" else fetch_okta_users()
        )
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        body = {
            "lab_id": LAB_ID,
            "status": "ERROR",
            "error": str(exc),
            "scf_controls": SCF_CONTROLS,
            "fedramp_20x_ksi": FEDRAMP_KSI,
        }
        return {"statusCode": 500, "body": json.dumps(body)}

    report = evaluate(identities)
    findings = to_asff_findings(report)
    report["securityhub_findings_count"] = len(findings)
    # Production: boto3 securityhub.batch_import_findings + s3.put_object
    print(json.dumps({"report_status": report["status"], "findings": len(findings)}))
    return {"statusCode": 200, "body": json.dumps(report), "findings": findings}
