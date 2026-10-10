package tfdrift.drift_test

import rego.v1

test_s3_cui_drift_001_fails if {
	result := data.tfdrift.drift.deny with input as {
		"resource_drift": [{
			"address": "aws_s3_bucket_policy.cui",
			"type": "aws_s3_bucket_policy",
		}],
	}
	some item in result
	item.rule_id == "S3-CUI-DRIFT-001"
	is_string(item.msg)
}

test_clean_plan_passes if {
	result := data.tfdrift.drift.deny with input as {"resource_drift": []}
	count(result) == 0
}

test_clean_evidence_passes if {
	result := data.tfdrift.drift.deny with input as {
		"lab_id": "16-terraform-drift-detection",
		"status": "PASS",
		"provenance": {"evidence_manifest_sha256": "abc"},
	}
	count(result) == 0
}

test_s3_cui_drift_001_fails_without_address if {
	result := data.tfdrift.drift.deny with input as {
		"resource_drift": [{"type": "aws_s3_bucket_policy"}],
	}
	some item in result
	item.rule_id == "S3-CUI-DRIFT-001"
	is_string(item.msg)
	item.resource == "aws_s3_bucket_policy"
}

test_s3_cui_drift_002_fails_without_count if {
	result := data.tfdrift.drift.deny with input as {
		"lab_id": "16-terraform-drift-detection",
		"status": "FAIL",
		"provenance": {"evidence_manifest_sha256": "abc"},
	}
	some item in result
	item.rule_id == "S3-CUI-DRIFT-002"
	is_string(item.msg)
}

test_s3_cui_drift_003_fails if {
	result := data.tfdrift.drift.deny with input as {
		"lab_id": "16-terraform-drift-detection",
		"status": "PASS",
		"provenance": {},
	}
	some item in result
	item.rule_id == "S3-CUI-DRIFT-003"
	is_string(item.msg)
}
