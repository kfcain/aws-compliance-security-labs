"""Shared runtime for the AWS compliance & security labs.

This module is vendored: the canonical copy lives at
``shared/lambda-common/lab_common.py`` and every lab carries a byte-identical
copy at ``labs/<id>/src/lab_common.py`` so exported standalone repos stay
self-contained. Edit the canonical copy and run
``node scripts/check-common-sync.mjs --write``.

Design contract (see SECURITY.md):

* Fail closed — an unconfigured lab reports ``CONFIG_ERROR``, never ``PASS``.
* Simulated data only enters via an explicit ``{"mode": "simulation"}`` event
  and every evidence artifact carries a ``data_source`` stamp.
* Partition / region / account come from the function's own ARN, never from
  hardcoded strings or spoofable environment defaults.
* Transport ``statusCode`` is 200 for any completed invocation; consumers
  branch on ``compliance_status``.
"""
from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

__all__ = [
    "Status",
    "ConfigError",
    "RuntimeContext",
    "EvidenceWriter",
    "AsffEmitter",
    "get_logger",
    "require_env",
    "get_bool_env",
    "get_int_env",
    "get_csv_env",
    "parse_iso8601",
    "coerce_bool",
    "utc_now",
    "new_run_id",
    "simulation_requested",
    "publish_alert",
    "respond",
]


class Status(str, Enum):
    """Compliance verdicts a lab may emit. There is no placeholder state:
    work that was not performed is CONFIG_ERROR or NOT_APPLICABLE."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    CONFIG_ERROR = "CONFIG_ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ConfigError(Exception):
    """Raised when required configuration is missing or malformed."""


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            entry.update(extra)
        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def get_logger(lab_id: str) -> logging.Logger:
    """Structured JSON logger. Level via LOG_LEVEL (default INFO)."""
    logger = logging.getLogger(lab_id)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())
    return logger


# --------------------------------------------------------------------------
# Runtime context (partition / region / account from the function ARN)
# --------------------------------------------------------------------------

_ARN_RE = re.compile(
    r"^arn:(?P<partition>[a-z0-9-]+):lambda:(?P<region>[a-z0-9-]+):(?P<account>\d{12}):"
)


@dataclass(frozen=True)
class RuntimeContext:
    partition: str
    region: str
    account_id: str

    @classmethod
    def from_arn(cls, arn: str) -> RuntimeContext:
        match = _ARN_RE.match(arn or "")
        if not match:
            raise ConfigError(f"cannot derive partition/region/account from ARN: {arn!r}")
        return cls(
            partition=match.group("partition"),
            region=match.group("region"),
            account_id=match.group("account"),
        )

    @classmethod
    def from_lambda(cls, context: Any) -> RuntimeContext:
        """Build from the live Lambda context object (authoritative), falling
        back to LAB_RUNTIME_ARN for local tests only."""
        arn = getattr(context, "invoked_function_arn", None) or os.environ.get("LAB_RUNTIME_ARN", "")
        return cls.from_arn(arn)

    @property
    def securityhub_product_arn(self) -> str:
        return (
            f"arn:{self.partition}:securityhub:{self.region}:{self.account_id}"
            f":product/{self.account_id}/default"
        )


# --------------------------------------------------------------------------
# Configuration helpers — read at handler time, strict, fail closed
# --------------------------------------------------------------------------

def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"required environment variable {name} is not set")
    return value


def get_bool_env(name: str, default: bool | None = None) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        if default is None:
            raise ConfigError(f"required boolean environment variable {name} is not set")
        return default
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise ConfigError(f"environment variable {name} must be 'true' or 'false', got {raw!r}")


def get_int_env(name: str, default: int | None = None) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        if default is None:
            raise ConfigError(f"required integer environment variable {name} is not set")
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"environment variable {name} must be an integer, got {raw!r}") from exc


def get_csv_env(name: str, default: list[str] | None = None) -> list[str]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        if default is None:
            raise ConfigError(f"required list environment variable {name} is not set")
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------

def parse_iso8601(value: str) -> datetime:
    """Parse an ISO-8601 timestamp into an *aware* datetime.

    Naive timestamps are interpreted as UTC — comparing naive and aware
    datetimes raised TypeError in earlier lab code; this is the single
    sanctioned parse path.
    """
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def coerce_bool(value: Any) -> bool | None:
    """Strict truthiness for evidence fields. JSON string "false" is False —
    Python truthiness on non-empty strings previously passed failed restore
    drills. Unknown shapes return None (treated as 'not reported')."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        return None
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    return None


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_run_id(context: Any) -> str:
    request_id = getattr(context, "aws_request_id", None)
    if request_id:
        return str(request_id)
    return utc_now().strftime("%Y%m%dT%H%M%S.%fZ")


def simulation_requested(event: dict[str, Any]) -> bool:
    """Simulation is an explicit opt-in; simulated evidence is stamped."""
    return isinstance(event, dict) and event.get("mode") == "simulation"


# --------------------------------------------------------------------------
# Evidence persistence
# --------------------------------------------------------------------------

class EvidenceWriter:
    """Writes the evidence artifact to the lab's evidence bucket as
    ``<lab_id>/<yyyy>/<mm>/<dd>/<run_id>.json``."""

    def __init__(self, lab_id: str, bucket: str | None = None, s3_client: Any = None):
        self.lab_id = lab_id
        self.bucket = bucket if bucket is not None else os.environ.get("EVIDENCE_BUCKET", "")
        if not self.bucket:
            raise ConfigError("EVIDENCE_BUCKET is not set — evidence cannot be persisted")
        if s3_client is None:  # pragma: no cover - exercised in AWS only
            import boto3

            s3_client = boto3.client("s3")
        self._s3 = s3_client

    def write(self, evidence: dict[str, Any], run_id: str) -> str:
        now = utc_now()
        key = f"{self.lab_id}/{now:%Y/%m/%d}/{run_id}.json"
        self._s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=json.dumps(evidence, default=str).encode("utf-8"),
            ContentType="application/json",
        )
        return f"s3://{self.bucket}/{key}"


# --------------------------------------------------------------------------
# Security Hub (ASFF)
# --------------------------------------------------------------------------

class AsffEmitter:
    """Builds and imports ASFF findings with a partition-correct ProductArn."""

    _BATCH = 100  # BatchImportFindings hard limit

    def __init__(self, lab_id: str, runtime: RuntimeContext, client: Any = None):
        self.lab_id = lab_id
        self.runtime = runtime
        if client is None:  # pragma: no cover - exercised in AWS only
            import boto3

            client = boto3.client("securityhub")
        self._client = client

    def build_finding(
        self,
        *,
        finding_id: str,
        title: str,
        description: str,
        severity: str,
        resource_type: str,
        resource_id: str,
        status: Status,
        extra_product_fields: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        now = utc_now().isoformat()
        product_fields = {"lab_id": self.lab_id, "compliance_status": status.value}
        if extra_product_fields:
            product_fields.update({k: str(v) for k, v in extra_product_fields.items()})
        return {
            "SchemaVersion": "2018-10-08",
            "Id": f"{self.lab_id}/{finding_id}",
            "ProductArn": self.runtime.securityhub_product_arn,
            "GeneratorId": self.lab_id,
            "AwsAccountId": self.runtime.account_id,
            "Types": ["Software and Configuration Checks/Compliance"],
            "CreatedAt": now,
            "UpdatedAt": now,
            "Severity": {"Label": severity},
            "Title": title,
            "Description": description[:1024],
            "Resources": [
                {
                    "Type": resource_type,
                    "Id": resource_id,
                    "Region": self.runtime.region,
                }
            ],
            "Compliance": {"Status": "PASSED" if status is Status.PASS else "FAILED"},
            "ProductFields": product_fields,
            "RecordState": "ACTIVE",
        }

    def emit(self, findings: Iterable[dict[str, Any]]) -> int:
        findings = list(findings)
        imported = 0
        for start in range(0, len(findings), self._BATCH):
            batch = findings[start : start + self._BATCH]
            response = self._client.batch_import_findings(Findings=batch)
            imported += int(response.get("SuccessCount", 0))
        return imported


# --------------------------------------------------------------------------
# Alerting + response envelope
# --------------------------------------------------------------------------

def publish_alert(
    lab_id: str,
    status: Status,
    summary: str,
    topic_arn: str | None = None,
    sns_client: Any = None,
) -> bool:
    """Publish an alert for non-PASS outcomes. Returns True when published."""
    topic_arn = topic_arn if topic_arn is not None else os.environ.get("SNS_TOPIC_ARN", "")
    if not topic_arn:
        raise ConfigError("SNS_TOPIC_ARN is not set — alerts cannot be delivered")
    if sns_client is None:  # pragma: no cover - exercised in AWS only
        import boto3

        sns_client = boto3.client("sns")
    sns_client.publish(
        TopicArn=topic_arn,
        Subject=f"[{lab_id}] {status.value}"[:100],
        Message=summary,
    )
    return True


def respond(status: Status, evidence: dict[str, Any]) -> dict[str, Any]:
    """Uniform handler response. ``statusCode`` is transport-only; consumers
    (Step Functions choices, dashboards) branch on ``compliance_status``."""
    evidence = dict(evidence)
    evidence["status"] = status.value
    return {
        "statusCode": 200,
        "compliance_status": status.value,
        "body": json.dumps(evidence, default=str),
    }
