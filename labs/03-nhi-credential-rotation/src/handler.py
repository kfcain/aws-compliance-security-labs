"""
Non-human identity (NHI) inventory + rotation orchestration stub.

Discovers IAM access keys older than MAX_KEY_AGE_DAYS and Secrets Manager
secrets lacking rotation. Integrates optionally with Okta/Descope M2M apps.
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any

LAB_ID = "03-nhi-credential-rotation"
SCF_CONTROLS = ["IAC-15", "IAC-21", "CRY-01", "CFG-02"]
FEDRAMP_KSI = ["KSI-IAM-ELP", "KSI-IAM-JIT", "KSI-SVC-SEC"]
MAX_KEY_AGE_DAYS = int(os.environ.get("MAX_KEY_AGE_DAYS", "90"))


def age_days(iso_ts: str) -> float:
    created = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    return (datetime.now(UTC) - created).total_seconds() / 86400.0


def evaluate_inventory(inventory: list[dict[str, Any]]) -> dict[str, Any]:
    stale = []
    for item in inventory:
        days = age_days(item["created_at"])
        needs_rotation = days >= MAX_KEY_AGE_DAYS or item.get("rotation_enabled") is False
        if needs_rotation:
            stale.append({**item, "age_days": round(days, 1)})
    return {
        "lab_id": LAB_ID,
        "checked_at": datetime.now(UTC).isoformat(),
        "status": "PASS" if not stale else "FAIL",
        "policy_max_key_age_days": MAX_KEY_AGE_DAYS,
        "inventory_count": len(inventory),
        "stale_count": len(stale),
        "stale_credentials": stale,
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "actions_recommended": [
            "Rotate IAM access key via CreateAccessKey + retire old key",
            "Enable Secrets Manager rotation Lambda",
            "Shorten M2M token TTL in Okta/Descope",
        ],
    }


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    inventory = event.get("inventory") or [
        {
            "type": "iam_access_key",
            "principal": "arn:aws:iam::123:user/ci-bot",
            "credential_id": "AKIADEMO",
            "created_at": "2024-01-01T00:00:00Z",
            "rotation_enabled": False,
        },
        {
            "type": "secretsmanager",
            "principal": "app/db/password",
            "credential_id": "secret-demo",
            "created_at": datetime.now(UTC).isoformat(),
            "rotation_enabled": True,
        },
    ]
    report = evaluate_inventory(inventory)
    print(json.dumps({"status": report["status"], "stale": report["stale_count"]}))
    return {"statusCode": 200, "body": json.dumps(report)}
