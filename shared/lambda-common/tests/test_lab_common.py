"""Unit tests for the canonical lab_common runtime."""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

CANONICAL = Path(__file__).parent.parent / "lab_common.py"
spec = importlib.util.spec_from_file_location("lab_common_canonical", CANONICAL)
lab_common = importlib.util.module_from_spec(spec)
sys.modules["lab_common_canonical"] = lab_common
spec.loader.exec_module(lab_common)

from conftest import FakeClient, FakeLambdaContext  # noqa: E402


class TestStatusContract:
    def test_no_placeholder_status_exists(self):
        assert "PASS_PLACEHOLDER" not in [s.value for s in lab_common.Status]

    def test_respond_transport_vs_compliance(self):
        result = lab_common.respond(lab_common.Status.FAIL, {"lab_id": "x"})
        assert result["statusCode"] == 200
        assert result["compliance_status"] == "FAIL"
        assert json.loads(result["body"])["status"] == "FAIL"


class TestRuntimeContext:
    def test_from_commercial_arn(self):
        rc = lab_common.RuntimeContext.from_arn(
            "arn:aws:lambda:us-east-1:123456789012:function:f"
        )
        assert (rc.partition, rc.region, rc.account_id) == ("aws", "us-east-1", "123456789012")

    def test_from_govcloud_arn(self):
        rc = lab_common.RuntimeContext.from_arn(
            "arn:aws-us-gov:lambda:us-gov-west-1:123456789012:function:f"
        )
        assert rc.partition == "aws-us-gov"
        assert rc.securityhub_product_arn == (
            "arn:aws-us-gov:securityhub:us-gov-west-1:123456789012"
            ":product/123456789012/default"
        )

    def test_garbage_arn_is_config_error(self):
        with pytest.raises(lab_common.ConfigError):
            lab_common.RuntimeContext.from_arn("not-an-arn")

    def test_from_lambda_context(self):
        rc = lab_common.RuntimeContext.from_lambda(FakeLambdaContext())
        assert rc.account_id == "123456789012"


class TestParsers:
    def test_naive_timestamp_treated_as_utc(self):
        parsed = lab_common.parse_iso8601("2026-01-01T00:00:00")
        assert parsed.tzinfo is not None
        # Must be comparable with aware datetimes (previously TypeError).
        assert parsed < datetime.now(UTC)

    def test_zulu_suffix(self):
        parsed = lab_common.parse_iso8601("2026-01-01T00:00:00Z")
        assert parsed.tzinfo is not None

    def test_coerce_bool_string_false_is_false(self):
        assert lab_common.coerce_bool("false") is False
        assert lab_common.coerce_bool("False") is False

    def test_coerce_bool_unknown_is_none(self):
        assert lab_common.coerce_bool("yes") is None
        assert lab_common.coerce_bool({}) is None

    def test_coerce_bool_real_bools(self):
        assert lab_common.coerce_bool(True) is True
        assert lab_common.coerce_bool(False) is False


class TestEnvHelpers:
    def test_require_env_missing_raises(self, monkeypatch):
        monkeypatch.delenv("NOPE", raising=False)
        with pytest.raises(lab_common.ConfigError):
            lab_common.require_env("NOPE")

    def test_bool_env_strict(self, monkeypatch):
        monkeypatch.setenv("FLAG", "yes")
        with pytest.raises(lab_common.ConfigError):
            lab_common.get_bool_env("FLAG")
        monkeypatch.setenv("FLAG", "true")
        assert lab_common.get_bool_env("FLAG") is True

    def test_int_env_strict(self, monkeypatch):
        monkeypatch.setenv("NUM", "abc")
        with pytest.raises(lab_common.ConfigError):
            lab_common.get_int_env("NUM")

    def test_csv_env(self, monkeypatch):
        monkeypatch.setenv("LIST", "a, b ,c,")
        assert lab_common.get_csv_env("LIST") == ["a", "b", "c"]


class TestEvidenceWriter:
    def test_writes_dated_key(self, monkeypatch):
        fake = FakeClient()
        writer = lab_common.EvidenceWriter("01-test", bucket="bkt", s3_client=fake)
        uri = writer.write({"status": "PASS"}, run_id="run-1")
        assert uri.startswith("s3://bkt/01-test/")
        assert uri.endswith("/run-1.json")
        put = fake.calls_to("put_object")[0]
        assert put["Bucket"] == "bkt"
        assert json.loads(put["Body"])["status"] == "PASS"

    def test_missing_bucket_is_config_error(self, monkeypatch):
        monkeypatch.delenv("EVIDENCE_BUCKET", raising=False)
        with pytest.raises(lab_common.ConfigError):
            lab_common.EvidenceWriter("01-test", s3_client=FakeClient())


class TestAsffEmitter:
    def _emitter(self, fake):
        rc = lab_common.RuntimeContext("aws-us-gov", "us-gov-west-1", "123456789012")
        return lab_common.AsffEmitter("11-test", rc, client=fake)

    def test_product_arn_partition_correct(self, fake_securityhub):
        emitter = self._emitter(fake_securityhub)
        finding = emitter.build_finding(
            finding_id="f1", title="t", description="d", severity="HIGH",
            resource_type="AwsS3Bucket", resource_id="arn:aws-us-gov:s3:::b",
            status=lab_common.Status.FAIL,
        )
        assert finding["ProductArn"].startswith("arn:aws-us-gov:securityhub:us-gov-west-1")
        assert finding["AwsAccountId"] == "123456789012"
        assert finding["Compliance"]["Status"] == "FAILED"

    def test_chunked_at_100(self):
        fake = FakeClient(responses={"batch_import_findings": {"SuccessCount": 100}})
        emitter = self._emitter(fake)
        finding = emitter.build_finding(
            finding_id="f", title="t", description="d", severity="LOW",
            resource_type="Other", resource_id="r", status=lab_common.Status.PASS,
        )
        emitter.emit([finding] * 250)
        batches = fake.calls_to("batch_import_findings")
        assert [len(b["Findings"]) for b in batches] == [100, 100, 50]


class TestAlerts:
    def test_publish_alert(self, fake_sns):
        ok = lab_common.publish_alert(
            "01-test", lab_common.Status.FAIL, "summary",
            topic_arn="arn:aws:sns:us-east-1:123456789012:t", sns_client=fake_sns,
        )
        assert ok is True
        assert fake_sns.calls_to("publish")[0]["Subject"] == "[01-test] FAIL"

    def test_missing_topic_is_config_error(self, monkeypatch, fake_sns):
        monkeypatch.delenv("SNS_TOPIC_ARN", raising=False)
        with pytest.raises(lab_common.ConfigError):
            lab_common.publish_alert("01-test", lab_common.Status.FAIL, "s", sns_client=fake_sns)


class TestSimulation:
    def test_simulation_requires_explicit_mode(self):
        assert lab_common.simulation_requested({"mode": "simulation"}) is True
        assert lab_common.simulation_requested({"simulate": True}) is False
        assert lab_common.simulation_requested({}) is False
