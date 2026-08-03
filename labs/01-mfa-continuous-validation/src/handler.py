"""Persistent MFA validation worker (Okta / Descope).

Continuously validates that every active human identity in the configured
IdP holds phishing-resistant MFA (WebAuthn / U2F / Okta FastPass
``signed_nonce``). Non-compliant identities become Security Hub ASFF
findings; every run persists a stamped evidence artifact.

Event sources:
  * Scheduled sweep (EventBridge) — users pulled live from the IdP
  * ``{"mode": "simulation"}`` — fixed demo identities, stamped as simulated

Environment contract:
  IDP_PROVIDER     ``okta`` | ``descope`` (default ``okta``)
  OKTA_DOMAIN      bare hostname of the Okta org (e.g. ``example.okta.com``)
                   — no scheme, no slashes; validated before any URL is built
  IDP_SECRET_ARN   Secrets Manager ARN holding the IdP API token (preferred)
  IDP_API_TOKEN    raw token in an env var (deprecated fallback — logs a
                   warning; the token itself is never logged)
  EVIDENCE_BUCKET  S3 bucket for evidence artifacts (required)
  SNS_TOPIC_ARN    alert topic for non-PASS outcomes (required)
  LOG_LEVEL        standard logging level (default INFO)
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
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

LAB_ID = "01-mfa-continuous-validation"
SCF_CONTROLS = ["IAC-06", "IAC-15", "IAC-21", "MON-01"]
FEDRAMP_KSI = ["KSI-IAM-MFA", "KSI-IAM-ELP", "KSI-AFR-PVL"]

logger = get_logger(LAB_ID)

# Factor types accepted as phishing-resistant (FIDO2/WebAuthn family).
PHISHING_RESISTANT_FACTORS = {"webauthn", "u2f", "signed_nonce"}

# Okta paginates via Link rel="next"; cap the walk so a misbehaving (or
# malicious) API cannot spin the function forever.
MAX_PAGES = 50

# Per-request timeout policy: never more than 10s per call, always leave
# 5s of Lambda budget for evidence write + alerting, and refuse to start a
# request that could not finish inside the remaining budget.
_MAX_REQUEST_TIMEOUT_S = 10.0
_RESERVED_BUDGET_S = 5.0
_MIN_REQUEST_TIMEOUT_S = 1.0

# Bare DNS hostname: letters/digits/hyphens in dot-separated labels.
# No scheme, no slashes, no userinfo, no port — anything else would let a
# poisoned OKTA_DOMAIN redirect the authenticated request elsewhere.
_HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


@dataclass
class IdentityMfaStatus:
    user_id: str
    email: str  # kept for the evidence artifact only — never in ASFF or logs
    mfa_enabled: bool
    phishing_resistant: bool
    factors: list[str]
    source: str


# --------------------------------------------------------------------------
# HTTP layer — injectable for tests; default is urllib WITHOUT redirects
# --------------------------------------------------------------------------

def _build_opener() -> urllib.request.OpenerDirector:
    """Opener with NO HTTPRedirectHandler.

    ``urllib.request.urlopen`` follows redirects and re-sends request headers
    — including ``Authorization: SSWS <token>`` — to whatever host the
    ``Location`` header names. With no redirect handler installed, any 3xx
    falls through to ``HTTPDefaultErrorHandler`` and raises ``HTTPError``
    instead of leaking the token cross-host.
    """
    opener = urllib.request.OpenerDirector()
    for handler_cls in (
        urllib.request.UnknownHandler,
        urllib.request.HTTPSHandler,
        urllib.request.HTTPDefaultErrorHandler,
        urllib.request.HTTPErrorProcessor,
    ):
        opener.add_handler(handler_cls())
    return opener


def _default_http_get(
    url: str, headers: dict[str, str], timeout: float
) -> tuple[int, dict[str, str], Any]:
    """Default ``http_get`` implementation: (status, headers, parsed JSON).

    Scheme is pinned to https and the host component is a validated bare
    hostname interpolated by us — ``file:``/custom schemes cannot reach here.
    """
    if not url.startswith("https://"):
        raise ConfigError(f"refusing non-https URL scheme in {url.split(':', 1)[0]!r}")
    # noqa justification: scheme enforced https just above; host validated by
    # _HOSTNAME_RE before interpolation; opener has no redirect handler.
    req = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310
    with _build_opener().open(req, timeout=timeout) as resp:  # noqa: S310
        body = json.loads(resp.read().decode("utf-8"))
        return int(resp.status), dict(resp.headers.items()), body


def _request_timeout(context: Any) -> float:
    """Per-request timeout derived from the remaining Lambda budget.

    The legacy fixed ``timeout=30`` allowed two slow calls to eat the whole
    60s function budget mid-population. Stop with an error instead of
    reporting a partially-checked population as authoritative.
    """
    remaining_s = context.get_remaining_time_in_millis() / 1000.0
    budget = remaining_s - _RESERVED_BUDGET_S
    if budget < _MIN_REQUEST_TIMEOUT_S:
        raise RuntimeError(
            f"Lambda time budget nearly exhausted ({remaining_s:.1f}s remaining); "
            "aborting IdP sweep rather than emitting a partial population"
        )
    return min(_MAX_REQUEST_TIMEOUT_S, budget)


def _link_next(headers: dict[str, str]) -> str | None:
    """Extract the ``rel="next"`` URL from an Okta ``Link`` response header."""
    link_value = ""
    for key, value in headers.items():
        if key.lower() == "link":
            link_value = value
            break
    # RFC 8288 lite: Okta next-links never contain commas, so a split is safe.
    for part in link_value.split(","):
        segments = part.split(";")
        url = segments[0].strip().strip("<>")
        if url and any(seg.strip().replace("'", '"') == 'rel="next"' for seg in segments[1:]):
            return url
    return None


# --------------------------------------------------------------------------
# Configuration — resolved at handler time, fail closed
# --------------------------------------------------------------------------

def validate_okta_domain(domain: str) -> str:
    """OKTA_DOMAIN must be a bare hostname before it touches a URL."""
    if not domain:
        raise ConfigError("OKTA_DOMAIN is not set — cannot query the Okta org")
    if not _HOSTNAME_RE.match(domain):
        raise ConfigError(
            f"OKTA_DOMAIN must be a bare hostname like 'example.okta.com' "
            f"(no scheme, no slashes), got: {domain!r}"
        )
    return domain


def resolve_api_token(secretsmanager_client: Any = None) -> str:
    """IdP API token: Secrets Manager (IDP_SECRET_ARN) preferred, env var
    IDP_API_TOKEN as a deprecated fallback. The token value is never logged."""
    secret_arn = os.environ.get("IDP_SECRET_ARN", "").strip()
    if secret_arn:
        if secretsmanager_client is None:  # pragma: no cover - AWS only
            import boto3

            secretsmanager_client = boto3.client("secretsmanager")
        response = secretsmanager_client.get_secret_value(SecretId=secret_arn)
        secret = response.get("SecretString") or ""
        try:  # accept either a raw token or a {"token": "..."} JSON secret
            parsed = json.loads(secret)
            if isinstance(parsed, dict):
                secret = parsed.get("token") or parsed.get("api_token") or ""
        except (json.JSONDecodeError, TypeError):
            pass
        if not secret:
            raise ConfigError("IDP_SECRET_ARN resolved to an empty secret value")
        return secret
    token = os.environ.get("IDP_API_TOKEN", "").strip()
    if token:
        logger.warning(
            "IDP_API_TOKEN env var is deprecated — store the token in "
            "Secrets Manager and set IDP_SECRET_ARN"
        )
        return token
    raise ConfigError(
        "no IdP API token configured: set IDP_SECRET_ARN (preferred) or IDP_API_TOKEN"
    )


# --------------------------------------------------------------------------
# IdP clients
# --------------------------------------------------------------------------

def fetch_okta_users(
    domain: str, token: str, http_get: Any, context: Any
) -> list[IdentityMfaStatus]:
    """List all ACTIVE Okta users and their factor enrollments.

    Follows ``Link: <...>; rel="next"`` pagination (bounded by MAX_PAGES) —
    the legacy single ``limit=50`` call silently truncated the population
    under audit. Query strings are built with ``urlencode``; the legacy
    hand-built filter contained raw spaces/quotes and raised
    ``http.client.InvalidURL`` on every configured run.
    """
    base = f"https://{domain}/api/v1"
    headers = {"Authorization": f"SSWS {token}", "Accept": "application/json"}
    query = urllib.parse.urlencode({"limit": "200", "filter": 'status eq "ACTIVE"'})
    url: str | None = f"{base}/users?{query}"

    users: list[dict[str, Any]] = []
    pages = 0
    while url:
        pages += 1
        if pages > MAX_PAGES:
            raise RuntimeError(f"Okta pagination exceeded the {MAX_PAGES}-page safety cap")
        status, resp_headers, body = http_get(url, headers, _request_timeout(context))
        if 300 <= status < 400:
            raise RuntimeError(
                f"Okta users API answered HTTP {status}; redirects are refused "
                "(following one would re-send the Authorization header cross-host)"
            )
        if status != 200:
            raise RuntimeError(f"Okta users API returned HTTP {status}")
        if not isinstance(body, list):
            raise RuntimeError("Okta users API returned a non-list body")
        users.extend(body)
        url = _link_next(resp_headers)
        if url and not url.startswith(f"https://{domain}/"):
            raise RuntimeError("Okta pagination next-link left the configured host; refusing")

    results: list[IdentityMfaStatus] = []
    for user in users:
        uid = user["id"]
        status, _, factors = http_get(
            f"{base}/users/{urllib.parse.quote(uid, safe='')}/factors",
            headers,
            _request_timeout(context),
        )
        if status != 200:
            raise RuntimeError(f"Okta factors API returned HTTP {status} for a user")
        types = [f.get("factorType", "") for f in factors if f.get("status") == "ACTIVE"]
        results.append(
            IdentityMfaStatus(
                user_id=uid,
                email=user.get("profile", {}).get("email", ""),
                mfa_enabled=len(types) > 0,
                phishing_resistant=any(t in PHISHING_RESISTANT_FACTORS for t in types),
                factors=types,
                source="okta",
            )
        )
    return results


def fetch_descope_users() -> list[IdentityMfaStatus]:
    """Descope Management API client — intentionally not implemented.

    Fail closed: the legacy code fell through to the Okta demo path and
    reported PASS for a tenant nobody had checked. Until a real Descope
    client ships, selecting the provider is a configuration error.
    """
    raise ConfigError(
        "IDP_PROVIDER=descope: the Descope Management API client is not "
        "implemented in this lab build; refusing to substitute demo data or "
        "the Okta path (fail closed). Deploy with IDP_PROVIDER=okta, or use "
        '{"mode": "simulation"} for stamped demo evidence.'
    )


def _simulation_identities() -> list[IdentityMfaStatus]:
    return [
        IdentityMfaStatus(
            user_id="sim-user-webauthn",
            email="sim-compliant@example.com",
            mfa_enabled=True,
            phishing_resistant=True,
            factors=["webauthn"],
            source="simulation",
        ),
        IdentityMfaStatus(
            user_id="sim-user-totp-only",
            email="sim-legacy@example.com",
            mfa_enabled=True,
            phishing_resistant=False,
            factors=["token:software:totp"],
            source="simulation",
        ),
    ]


# --------------------------------------------------------------------------
# Evaluation + evidence + ASFF
# --------------------------------------------------------------------------

def evaluate(
    identities: list[IdentityMfaStatus], data_source: str, idp_provider: str
) -> dict[str, Any]:
    failures = [
        asdict(i) for i in identities if not (i.mfa_enabled and i.phishing_resistant)
    ]
    status = Status.PASS if not failures else Status.FAIL
    return {
        "lab_id": LAB_ID,
        "checked_at": utc_now().isoformat(),
        "status": status.value,
        "data_source": data_source,
        "idp_provider": idp_provider,
        "checked_count": len(identities),
        "mfa_enrolled_count": sum(1 for i in identities if i.mfa_enabled),
        "phishing_resistant_count": sum(1 for i in identities if i.phishing_resistant),
        "failure_count": len(failures),
        # Per-user detail stays in the evidence artifact (encrypted bucket);
        # ASFF findings and log lines carry user IDs only.
        "failures": failures,
        "scf_controls": SCF_CONTROLS,
        "fedramp_20x_ksi": FEDRAMP_KSI,
        "policy": {
            "require_mfa": True,
            "require_phishing_resistant": True,
            "accepted_factors": sorted(PHISHING_RESISTANT_FACTORS),
        },
    }


def build_asff_findings(evidence: dict[str, Any], emitter: AsffEmitter) -> list[dict[str, Any]]:
    """One HIGH finding per non-compliant identity.

    Descriptions reference IdP user IDs only — emails never enter Security
    Hub or CloudWatch Logs.
    """
    findings = []
    for fail in evidence["failures"]:
        findings.append(
            emitter.build_finding(
                finding_id=f"mfa/{fail['user_id']}",
                title="Human identity missing phishing-resistant MFA",
                description=(
                    f"IdP user {fail['user_id']} (source={fail['source']}) has active "
                    f"factors {fail['factors'] or 'none'} and does not satisfy the "
                    "phishing-resistant MFA policy. Maps to SCF IAC-06 / FedRAMP KSI-IAM-MFA."
                ),
                severity="HIGH",
                resource_type="Other",
                resource_id=f"idp-user/{fail['user_id']}",
                status=Status.FAIL,
                extra_product_fields={
                    "idp_provider": evidence["idp_provider"],
                    "data_source": evidence["data_source"],
                },
            )
        )
    return findings


# --------------------------------------------------------------------------
# Handler
# --------------------------------------------------------------------------

def handler(
    event: dict[str, Any],
    context: Any,
    http_get: Any = None,
    secretsmanager_client: Any = None,
    s3_client: Any = None,
    sns_client: Any = None,
    securityhub_client: Any = None,
) -> dict[str, Any]:
    run_id = new_run_id(context)
    try:
        runtime = RuntimeContext.from_lambda(context)  # fail closed on unknown partition
        provider = (os.environ.get("IDP_PROVIDER", "").strip().lower() or "okta")

        if simulation_requested(event):
            identities = _simulation_identities()
            data_source = "simulation"
        elif provider == "okta":
            domain = validate_okta_domain(os.environ.get("OKTA_DOMAIN", "").strip())
            token = resolve_api_token(secretsmanager_client)
            identities = fetch_okta_users(
                domain, token, http_get or _default_http_get, context
            )
            data_source = "okta"
        elif provider == "descope":
            identities = fetch_descope_users()  # raises ConfigError (fail closed)
            data_source = "descope"
        else:
            raise ConfigError(
                f"unknown IDP_PROVIDER {provider!r}; expected 'okta' or 'descope'"
            )

        evidence = evaluate(identities, data_source, provider)
        status = Status(evidence["status"])

        if evidence["failures"]:
            emitter = AsffEmitter(LAB_ID, runtime, client=securityhub_client)
            findings = build_asff_findings(evidence, emitter)
            evidence["securityhub_findings_imported"] = emitter.emit(findings)
        else:
            findings = []
        evidence["securityhub_findings_count"] = len(findings)

        evidence["evidence_uri"] = EvidenceWriter(LAB_ID, s3_client=s3_client).write(
            evidence, run_id
        )
        if status is not Status.PASS:
            publish_alert(
                LAB_ID,
                status,
                f"{evidence['failure_count']} of {evidence['checked_count']} "
                "identities lack phishing-resistant MFA",
                sns_client=sns_client,
            )
        logger.info(
            "mfa sweep complete",
            extra={"extra_fields": {
                "run_id": run_id,
                "status": status.value,
                "checked": evidence["checked_count"],
                "failures": evidence["failure_count"],
                "data_source": data_source,
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
