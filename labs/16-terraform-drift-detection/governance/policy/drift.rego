# OPA / Conftest policy for the two-sided drift-control gate.
#
# Pre-deployment:  conftest test tfplan.json  --policy governance/policy
#   (evaluates the intended `terraform show -json` plan before apply)
# Post-deployment: conftest test evidence.json --policy governance/policy
#   (evaluates the Lambda's emitted evidence object after apply)
#
# Each violation carries the assessment objectives it maps to, so a failing
# gate produces the same objective-linked result shape as the handler's
# assurance case (see README).
package tfdrift.drift

import future.keywords.if
import future.keywords.in

# Resource-address / attribute globs that must never drift out of band.
# Mirrors the handler's critical-severity classes (KSI-CNA-EIS).
critical_patterns := [
	"aws_security_group",
	"aws_security_group_rule",
	"aws_iam_policy",
	"aws_iam_role_policy",
	"aws_s3_bucket_policy",
	"aws_kms_key",
]

# --- pre-deploy: a refresh-only plan must show no drift on critical types ---

resource_drift := input.resource_drift

deny contains result if {
	some change in resource_drift
	some pattern in critical_patterns
	startswith(change.type, pattern)
	result := {
		"rule_id": "S3-CUI-DRIFT-001",
		"resource": change.address,
		"result": "FAIL",
		"reason": sprintf("out-of-band drift on critical resource type %q", [change.type]),
		"assessment_objectives": ["03.04.01.a", "03.04.02.a", "A.03.04.03.ODP[01]"],
	}
}

# --- post-deploy: the emitted evidence must be a clean, sealed assurance case ---

deny contains result if {
	input.lab_id == "16-terraform-drift-detection"
	input.status == "FAIL"
	result := {
		"rule_id": "S3-CUI-DRIFT-002",
		"resource": "assurance_case",
		"result": "FAIL",
		"reason": sprintf("%d actionable drift(s) at or above threshold", [input.actionable_drift_count]),
		"assessment_objectives": ["03.04.02.b", "03.12.03"],
	}
}

deny contains result if {
	input.lab_id == "16-terraform-drift-detection"
	not input.provenance.evidence_manifest_sha256
	result := {
		"rule_id": "S3-CUI-DRIFT-003",
		"resource": "provenance",
		"result": "FAIL",
		"reason": "evidence package is not sealed with an integrity manifest",
		"assessment_objectives": ["03.12.01"],
	}
}
