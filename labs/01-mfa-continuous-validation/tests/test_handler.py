"""Regression + behavior tests for lab 01 (MFA continuous validation)."""
from __future__ import annotations

import json
import urllib.request

import pytest

from conftest import FakeClient, FakeLambdaContext, load_lab_module

handler_mod = load_lab_module("01-mfa-continuous-validation")

OKTA_DOMAIN = "example.okta.com"
WEBAUTHN_FACTORS = [{"factorType": "webauthn", "status": "ACTIVE"}]
TOTP_FACTORS = [{"factorType": "token:software:totp", "status": "ACTIVE"}]


class FakeHttp:
    """Injectable http_get double. ``routes`` is an ordered list of
    (url_substring, response) pairs; a response is (status, headers, body)
    or an Exception to raise. Every call is recorded in ``calls``."""

    def __init__(self, routes):
        self.routes = routes
        self.calls: list[tuple[str, dict, float]] = []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, headers, timeout))
        for needle, response in self.routes:
            if needle in url:
                if isinstance(response, Exception):
                    raise response
                return response
        raise AssertionError(f"unexpected URL fetched: {url}")


def _user(uid):
    return {"id": uid, "status": "ACTIVE", "profile": {"email": f"{uid}@example.com"}}


def _invoke(event, ctx, *, http=None, fakes=None):
    fakes = fakes or {}
    clients = {
        "s3": fakes.get("s3") or FakeClient(),
        "sns": fakes.get("sns") or FakeClient(),
        "securityhub": fakes.get("securityhub")
        or FakeClient(responses={"batch_import_findings": {"SuccessCount": 1, "FailedCount": 0}}),
        "secretsmanager": fakes.get("secretsmanager") or FakeClient(),
    }
    result = handler_mod.handler(
        event, ctx,
        http_get=http,
        secretsmanager_client=clients["secretsmanager"],
        s3_client=clients["s3"],
        sns_client=clients["sns"],
        securityhub_client=clients["securityhub"],
    )
    return result, clients


@pytest.fixture(autouse=True)
def _idp_env(monkeypatch):
    """No IdP configuration leaks in from the host environment."""
    for var in ("IDP_PROVIDER", "OKTA_DOMAIN", "DESCOPE_PROJECT_ID",
                "IDP_API_TOKEN", "IDP_SECRET_ARN"):
        monkeypatch.delenv(var, raising=False)


def _configure_okta(monkeypatch):
    monkeypatch.setenv("OKTA_DOMAIN", OKTA_DOMAIN)
    monkeypatch.setenv("IDP_API_TOKEN", "env-okta-token")


# --------------------------------------------------------------------------
# URL construction
# --------------------------------------------------------------------------

def test_okta_url_is_percent_encoded(lambda_context, monkeypatch):
    """Regression: the hand-built ``filter=status eq "ACTIVE"`` query raised
    http.client.InvalidURL (spaces/quotes) on every configured run, and
    InvalidURL was not caught by the URLError handler."""
    _configure_okta(monkeypatch)
    http = FakeHttp([
        ("/factors", (200, {}, WEBAUTHN_FACTORS)),
        ("/users?", (200, {}, [_user("u1")])),
    ])
    result, _ = _invoke({}, lambda_context, http=http)
    assert result["compliance_status"] == "PASS"
    users_url = http.calls[0][0]
    assert (
        "filter=status+eq+%22ACTIVE%22" in users_url
        or "filter=status%20eq%20%22ACTIVE%22" in users_url
    )
    assert " " not in users_url and '"' not in users_url
    # Per-request timeout is budget-derived, never the legacy fixed 30s.
    assert all(timeout <= 10 for _, _, timeout in http.calls)


# --------------------------------------------------------------------------
# Fail-closed configuration
# --------------------------------------------------------------------------

def test_unconfigured_returns_config_error_not_pass(lambda_context):
    """Regression: missing OKTA_DOMAIN/token returned a synthetic compliant
    demo user and a PASS verdict for a tenant nobody had checked."""
    result, clients = _invoke({}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"
    body = json.loads(result["body"])
    assert body["status"] != "PASS"
    assert not clients["s3"].calls_to("put_object"), "no evidence for unperformed work"


def test_descope_unconfigured_is_config_error(lambda_context, monkeypatch):
    """Regression: IDP_PROVIDER=descope fell through to the Okta demo path
    and reported PASS."""
    monkeypatch.setenv("IDP_PROVIDER", "descope")
    result, _ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"
    assert "descope" in json.loads(result["body"])["error"].lower()


def test_unknown_provider_is_config_error(lambda_context, monkeypatch):
    monkeypatch.setenv("IDP_PROVIDER", "azuread")
    result, _ = _invoke({}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


def test_bad_okta_domain_is_config_error(lambda_context, monkeypatch):
    """OKTA_DOMAIN must be a bare hostname — a scheme or path could point the
    authenticated request anywhere."""
    monkeypatch.setenv("OKTA_DOMAIN", "https://evil.example.com/api")
    monkeypatch.setenv("IDP_API_TOKEN", "env-okta-token")
    http = FakeHttp([])
    result, _ = _invoke({}, lambda_context, http=http)
    assert result["compliance_status"] == "CONFIG_ERROR"
    assert not http.calls


def test_missing_bucket_is_config_error(lambda_context, monkeypatch):
    monkeypatch.delenv("EVIDENCE_BUCKET")
    result, _ = _invoke({"mode": "simulation"}, lambda_context)
    assert result["compliance_status"] == "CONFIG_ERROR"


# --------------------------------------------------------------------------
# Simulation
# --------------------------------------------------------------------------

def test_simulation_is_stamped(lambda_context):
    result, _ = _invoke({"mode": "simulation"}, lambda_context)
    body = json.loads(result["body"])
    assert body["data_source"] == "simulation"
    assert body["checked_count"] == 2
    # The simulated population includes a TOTP-only identity: FAIL, stamped.
    assert result["compliance_status"] == "FAIL"


# --------------------------------------------------------------------------
# Redirects
# --------------------------------------------------------------------------

def test_no_redirect_follow(lambda_context, monkeypatch):
    """Regression: urlopen followed 3xx and re-sent ``Authorization: SSWS``
    to the redirect target's host. A 302 must be an ERROR, never followed."""
    _configure_okta(monkeypatch)
    http = FakeHttp([
        ("/users?", (302, {"Location": "https://evil.example.com/capture"}, [])),
    ])
    result, _ = _invoke({}, lambda_context, http=http)
    assert result["compliance_status"] == "ERROR"
    assert len(http.calls) == 1, "the Location target must never be fetched"
    assert all("evil.example.com" not in url for url, _, _ in http.calls)
    # The default transport is built without any redirect handler at all.
    opener = handler_mod._build_opener()
    assert not any(
        isinstance(h, urllib.request.HTTPRedirectHandler) for h in opener.handlers
    )


# --------------------------------------------------------------------------
# Pagination
# --------------------------------------------------------------------------

def test_link_header_pagination(lambda_context, monkeypatch):
    """Regression: a single ``limit=50`` call silently truncated the audited
    population. Both pages must land in the evidence population count."""
    _configure_okta(monkeypatch)
    base = f"https://{OKTA_DOMAIN}/api/v1/users"
    link = f'<{base}?limit=200>; rel="self", <{base}?after=cursor1&limit=200>; rel="next"'
    http = FakeHttp([
        ("/factors", (200, {}, WEBAUTHN_FACTORS)),
        ("after=cursor1", (200, {}, [_user("u2")])),
        ("/users?", (200, {"Link": link}, [_user("u1")])),
    ])
    result, _ = _invoke({}, lambda_context, http=http)
    body = json.loads(result["body"])
    assert body["checked_count"] == 2
    assert result["compliance_status"] == "PASS"


def test_pagination_never_leaves_okta_host(lambda_context, monkeypatch):
    _configure_okta(monkeypatch)
    link = '<https://evil.example.com/api/v1/users?after=x>; rel="next"'
    http = FakeHttp([("/users?", (200, {"Link": link}, [_user("u1")]))])
    result, _ = _invoke({}, lambda_context, http=http)
    assert result["compliance_status"] == "ERROR"
    assert all("evil.example.com" not in url for url, _, _ in http.calls)


# --------------------------------------------------------------------------
# Time budget
# --------------------------------------------------------------------------

def test_exhausted_time_budget_is_error(monkeypatch):
    """With almost no Lambda budget left, stop with ERROR instead of starting
    IdP calls that would report a partial population."""
    _configure_okta(monkeypatch)
    ctx = FakeLambdaContext(remaining_ms=4_000)
    http = FakeHttp([("/users?", (200, {}, []))])
    result, _ = _invoke({}, ctx, http=http)
    assert result["compliance_status"] == "ERROR"
    assert not http.calls


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

def test_token_from_secrets_manager(lambda_context, monkeypatch):
    secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:okta-api-token"
    monkeypatch.setenv("OKTA_DOMAIN", OKTA_DOMAIN)
    monkeypatch.setenv("IDP_SECRET_ARN", secret_arn)
    secretsmanager = FakeClient(
        responses={"get_secret_value": {"SecretString": "sm-okta-token-123"}}
    )
    http = FakeHttp([("/users?", (200, {}, []))])
    result, clients = _invoke(
        {}, lambda_context, http=http, fakes={"secretsmanager": secretsmanager}
    )
    assert result["compliance_status"] == "PASS"
    assert secretsmanager.calls_to("get_secret_value")[0]["SecretId"] == secret_arn
    assert http.calls[0][1]["Authorization"] == "SSWS sm-okta-token-123"
    # The token never appears in the response envelope.
    assert "sm-okta-token-123" not in json.dumps(result)


# --------------------------------------------------------------------------
# ASFF
# --------------------------------------------------------------------------

def test_asff_uses_context_account(govcloud_context):
    """Regression: ProductArn/AwsAccountId came from a spoofable
    AWS_ACCOUNT_ID env default ('000000000000') and a hardcoded aws
    partition. They must come from the function's own ARN."""
    result, clients = _invoke({"mode": "simulation"}, govcloud_context)
    assert result["compliance_status"] == "FAIL"
    batches = clients["securityhub"].calls_to("batch_import_findings")
    assert batches, "non-compliant identities must be imported to Security Hub"
    finding = batches[0]["Findings"][0]
    assert "arn:aws-us-gov" in finding["ProductArn"]
    assert finding["AwsAccountId"] == "123456789012"


def test_asff_description_has_user_ids_not_emails(lambda_context, monkeypatch):
    _configure_okta(monkeypatch)
    http = FakeHttp([
        ("/factors", (200, {}, TOTP_FACTORS)),
        ("/users?", (200, {}, [_user("u-legacy")])),
    ])
    result, clients = _invoke({}, lambda_context, http=http)
    assert result["compliance_status"] == "FAIL"
    finding = clients["securityhub"].calls_to("batch_import_findings")[0]["Findings"][0]
    assert "u-legacy" in finding["Description"]
    assert "@" not in finding["Description"], "emails must never enter ASFF"
    assert "@" not in finding["Title"]


# --------------------------------------------------------------------------
# Evidence + alerting
# --------------------------------------------------------------------------

def test_evidence_written_and_alert_on_fail(lambda_context):
    result, clients = _invoke({"mode": "simulation"}, lambda_context)
    assert result["compliance_status"] == "FAIL"
    put = clients["s3"].calls_to("put_object")
    assert put and put[0]["Bucket"] == "test-evidence-bucket"
    body = json.loads(result["body"])
    assert body["evidence_uri"].startswith("s3://test-evidence-bucket/")
    assert clients["sns"].calls_to("publish"), "non-PASS must alert"
    # Alert text summarizes counts — no emails.
    assert "@" not in clients["sns"].calls_to("publish")[0]["Message"]


def test_pass_makes_no_findings_and_no_alert(lambda_context, monkeypatch):
    _configure_okta(monkeypatch)
    http = FakeHttp([
        ("/factors", (200, {}, WEBAUTHN_FACTORS)),
        ("/users?", (200, {}, [_user("u1"), _user("u2")])),
    ])
    result, clients = _invoke({}, lambda_context, http=http)
    assert result["compliance_status"] == "PASS"
    body = json.loads(result["body"])
    assert body["data_source"] == "okta"
    assert body["securityhub_findings_count"] == 0
    assert not clients["securityhub"].calls_to("batch_import_findings")
    assert not clients["sns"].calls_to("publish")
    assert clients["s3"].calls_to("put_object"), "PASS evidence is still persisted"


def test_totp_only_user_fails_policy(lambda_context, monkeypatch):
    """Domain check: MFA-enrolled but not phishing-resistant is still a FAIL."""
    _configure_okta(monkeypatch)
    http = FakeHttp([
        ("/users/u-totp/factors", (200, {}, TOTP_FACTORS)),
        ("/users/u-none/factors", (200, {}, [])),
        ("/users?", (200, {}, [_user("u-totp"), _user("u-none")])),
    ])
    result, _ = _invoke({}, lambda_context, http=http)
    body = json.loads(result["body"])
    assert result["compliance_status"] == "FAIL"
    assert body["failure_count"] == 2
    by_id = {f["user_id"]: f for f in body["failures"]}
    assert by_id["u-totp"]["mfa_enabled"] and not by_id["u-totp"]["phishing_resistant"]
    assert not by_id["u-none"]["mfa_enabled"]
