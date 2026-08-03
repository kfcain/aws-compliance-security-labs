# OPA / Conftest gate for the emitted DR-readiness evidence.
#
#   conftest test evidence.json --policy governance/policy
#
# Each violation carries the assessment objectives it maps to, so a failing
# gate produces the same objective-linked result shape as the handler's
# assurance case.
package tfdr.readiness

import future.keywords.if
import future.keywords.in

deny contains result if {
	input.lab_id == "17-terraform-dr-readiness"
	input.state_backend_type == "local"
	result := {
		"rule_id": "DR-STATE-001",
		"resource": "state_backend",
		"result": "FAIL",
		"reason": "Terraform state backend is local — the IaC control plane is not recoverable",
		"assessment_objectives": ["03.04.01.a", "A.03.04.01.ODP[01]"],
	}
}

deny contains result if {
	input.lab_id == "17-terraform-dr-readiness"
	some finding in input.findings
	finding.code == "store-not-cross-region-durable"
	result := {
		"rule_id": "DR-RPO-002",
		"resource": finding.detail,
		"result": "FAIL",
		"reason": "Critical store has no cross-region durability — RPO cannot be met",
		"assessment_objectives": ["03.08.09.a", "A.03.08.09.ODP[01]"],
	}
}

deny contains result if {
	input.lab_id == "17-terraform-dr-readiness"
	input.status == "FAIL"
	result := {
		"rule_id": "DR-READY-003",
		"resource": "assurance_case",
		"result": "FAIL",
		"reason": sprintf("%d actionable DR-readiness gap(s) at or above threshold", [input.actionable_finding_count]),
		"assessment_objectives": ["A.03.06.02.ODP[01]"],
	}
}

deny contains result if {
	input.lab_id == "17-terraform-dr-readiness"
	not input.provenance.evidence_manifest_sha256
	result := {
		"rule_id": "DR-PROV-004",
		"resource": "provenance",
		"result": "FAIL",
		"reason": "evidence package is not sealed with an integrity manifest",
		"assessment_objectives": ["03.04.01.a"],
	}
}
