#!/usr/bin/env bash
# Producer-side, read-only DR-descriptor deriver.
#
# Builds the DR-readiness descriptor the lab's Lambda evaluates, from:
#   * the Terraform backend config (state-backend resilience), and
#   * `terraform show -json` (declared architecture: regions, data stores).
#
# Runs from a Terraform directory. Emits the descriptor JSON on stdout; upload
# it to DESCRIPTOR_BUCKET/DESCRIPTOR_KEY (see README). This is a REFERENCE
# implementation — the resource-attribute extraction is intentionally simple
# and should be tuned to your module conventions. Requires: terraform, jq.
#
# The heredoc jq program reads two inputs (backend descriptor + plan JSON) so no
# shell values are interpolated into code.
set -euo pipefail
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

primary_region="${PRIMARY_REGION:-$(terraform output -raw primary_region 2>/dev/null || echo "unknown")}"
recovery_region="${RECOVERY_REGION:-$(terraform output -raw recovery_region 2>/dev/null || echo "")}"
rto="${DECLARED_RTO_MINUTES:-}"
rpo="${DECLARED_RPO_MINUTES:-}"

# Backend descriptor. Terraform does not expose the full backend config via CLI,
# so this reads a committed backend descriptor file when present; otherwise it
# emits a conservative "local" backend so the lab fails closed until wired.
backend_file="${BACKEND_DESCRIPTOR_FILE:-backend.dr.json}"
if [ -f "$backend_file" ]; then
  backend_json="$(cat "$backend_file")"
else
  backend_json='{"backend_type":"local"}'
fi

plan_json="$(mktemp)"
trap 'rm -f "$plan_json"' EXIT
terraform show -json > "$plan_json" 2>/dev/null || echo '{}' > "$plan_json"

# Map planned resources -> critical data stores. Extend the type list to match
# the stores your baseline treats as CUI/mission-critical.
jq -n \
  --argjson backend "$backend_json" \
  --arg primary "$primary_region" \
  --arg recovery "$recovery_region" \
  --arg rto "$rto" \
  --arg rpo "$rpo" \
  --slurpfile plan "$plan_json" '
  ($plan[0].values.root_module.resources // []) as $res
  | {
      backend: $backend,
      primary_region: $primary,
      recovery_region: (if $recovery == "" then null else $recovery end),
      failover_routing: ([ $res[] | select(.type=="aws_route53_health_check") ] | length > 0),
      declared_rto_minutes: (if $rto == "" then null else ($rto|tonumber) end),
      declared_rpo_minutes: (if $rpo == "" then null else ($rpo|tonumber) end),
      data_stores: [
        $res[]
        | select(.type == "aws_s3_bucket" or .type == "aws_dynamodb_table" or .type == "aws_db_instance")
        | {
            address: .address,
            store_type: .type,
            critical: ((.values.tags.data_classification // "") == "CUI"
                        or (.values.tags.availability // "") == "mission-critical"),
            cross_region_replication:
              ((.values.replication_configuration // null) != null
                or (.values.replica // []) != []),
            point_in_time_recovery:
              ((.values.point_in_time_recovery // [] | if type=="array" then (.[0].enabled // false) else . end) == true),
            cross_region_backup: false
          }
      ]
    }'
