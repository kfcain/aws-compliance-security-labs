package tfdr.readiness_test

import rego.v1

good := {
	"lab_id": "17-terraform-dr-readiness",
	"state_backend_type": "s3",
	"status": "PASS",
	"findings": [],
	"provenance": {"evidence_manifest_sha256": "abc"},
}

test_dr_state_001_fails if {
	result := data.tfdr.readiness.deny with input as object.union(good, {"state_backend_type": "local"})
	some item in result
	item.rule_id == "DR-STATE-001"
	is_string(item.msg)
}

test_dr_ready_003_fails if {
	result := data.tfdr.readiness.deny with input as object.union(good, {
		"status": "FAIL",
		"actionable_finding_count": 2,
	})
	some item in result
	item.rule_id == "DR-READY-003"
	is_string(item.msg)
}

test_dr_prov_004_fails if {
	result := data.tfdr.readiness.deny with input as {
		"lab_id": "17-terraform-dr-readiness",
		"state_backend_type": "s3",
		"status": "PASS",
		"findings": [],
		"provenance": {},
	}
	some item in result
	item.rule_id == "DR-PROV-004"
	is_string(item.msg)
}

test_dr_rpo_002_fails_without_detail if {
	result := data.tfdr.readiness.deny with input as object.union(good, {
		"findings": [{"code": "store-not-cross-region-durable"}],
	})
	some item in result
	item.rule_id == "DR-RPO-002"
	is_string(item.msg)
	item.resource == "store-not-cross-region-durable"
}

test_dr_ready_003_fails_without_count if {
	result := data.tfdr.readiness.deny with input as object.union(good, {"status": "FAIL"})
	some item in result
	item.rule_id == "DR-READY-003"
	is_string(item.msg)
}

test_good_evidence_passes if {
	result := data.tfdr.readiness.deny with input as good
	count(result) == 0
}
