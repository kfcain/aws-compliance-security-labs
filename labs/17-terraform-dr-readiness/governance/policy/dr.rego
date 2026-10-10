# OPA / Conftest gate for the emitted DR-readiness evidence.
#
#   conftest test evidence.json --policy governance/policy --namespace tfdr.readiness
#
# The package is tfdr.readiness. Conftest's default namespace is main, which
# evaluates 0 rules and exits 0. Pass --namespace (or --all-namespaces).
# Each deny object includes a string msg so --all-namespaces can report it.
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
		"msg": "DR-STATE-001: Terraform state backend is local — the IaC control plane is not recoverable",
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
		"msg": "DR-RPO-002: Critical store has no cross-region durability — RPO cannot be met",
		"rule_id": "DR-RPO-002",
		"resource": object.get(finding, "detail", finding.code),
		"result": "FAIL",
		"reason": "Critical store has no cross-region durability — RPO cannot be met",
		"assessment_objectives": ["03.08.09.a", "A.03.08.09.ODP[01]"],
	}
}

deny contains result if {
	input.lab_id == "17-terraform-dr-readiness"
	input.status == "FAIL"
	gap_count := object.get(input, "actionable_finding_count", 0)
	result := {
		"msg": sprintf("DR-READY-003: %d actionable DR-readiness gap(s) at or above threshold", [gap_count]),
		"rule_id": "DR-READY-003",
		"resource": "assurance_case",
		"result": "FAIL",
		"reason": sprintf("%d actionable DR-readiness gap(s) at or above threshold", [gap_count]),
		"assessment_objectives": ["A.03.06.02.ODP[01]"],
	}
}

deny contains result if {
	input.lab_id == "17-terraform-dr-readiness"
	not input.provenance.evidence_manifest_sha256
	result := {
		"msg": "DR-PROV-004: evidence package is not sealed with an integrity manifest",
		"rule_id": "DR-PROV-004",
		"resource": "provenance",
		"result": "FAIL",
		"reason": "evidence package is not sealed with an integrity manifest",
		"assessment_objectives": ["03.04.01.a"],
	}
}
