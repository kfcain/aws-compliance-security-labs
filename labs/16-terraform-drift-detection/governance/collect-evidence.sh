#!/usr/bin/env bash
# Producer-side, point-in-time AWS evidence collector (read-only).
#
# Runs from a Terraform directory with a READ-ONLY audit profile and captures a
# machine-readable evidence package tied to the current Terraform commit and a
# refresh-only drift plan. Console screenshots are supplemental — this is the
# primary evidence. The output feeds the lab's assurance case (upload the
# resulting plan JSON to PLAN_BUCKET/PLAN_KEY for the Lambda to evaluate).
#
# An error file is evidence too: it shows a capability (Object Lock, a bucket
# policy) was not configured, or that the collector lacked access.
#
# Usage:
#   AWS_PROFILE=grc-lab-audit AWS_REGION=us-east-1 \
#   BUCKET=grc-lab-cui-store KMS_KEY_ARN=arn:... TRAIL_ARN=arn:... \
#   ./collect-evidence.sh
#
# Do NOT place raw terraform.tfstate or `terraform show -json` of state in an
# ordinary evidence repo — it can expose sensitive values in plaintext. This
# script collects a refresh-only PLAN (drift) and read-only API config only.
set -euo pipefail

: "${AWS_REGION:?set AWS_REGION}"
: "${BUCKET:?set BUCKET (the S3 bucket under assessment)}"
: "${KMS_KEY_ARN:?set KMS_KEY_ARN}"
: "${TRAIL_ARN:?set TRAIL_ARN}"
export AWS_PAGER=""

run="evidence/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$run"/{meta,s3,kms,cloudtrail,config,terraform,git}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$run/meta/collected-at.txt"
aws --version                         > "$run/meta/aws-cli-version.txt" 2>&1
aws sts get-caller-identity --output json > "$run/meta/collector-identity.json"
account_id="$(aws sts get-caller-identity --query Account --output text)"

# --- capture: run <output-file> -- <aws args...> ; stderr becomes .error.txt ---
capture() {
  local out="$1"; shift
  [ "$1" = "--" ] && shift
  "$@" > "$out" 2> "${out%.json}.error.txt" || true
}

# S3 configuration evidence (read-only)
for pair in \
  "location.json:get-bucket-location" \
  "tags.json:get-bucket-tagging" \
  "encryption.json:get-bucket-encryption" \
  "public-access-block.json:get-public-access-block" \
  "versioning.json:get-bucket-versioning" \
  "bucket-policy.json:get-bucket-policy" \
  "policy-status.json:get-bucket-policy-status" \
  "ownership-controls.json:get-bucket-ownership-controls" \
  "logging.json:get-bucket-logging" \
  "object-lock.json:get-object-lock-configuration"; do
  out="${pair%%:*}"; api="${pair##*:}"
  capture "$run/s3/$out" -- aws s3api "$api" --bucket "$BUCKET" --output json
done
capture "$run/s3/account-public-access-block.json" -- \
  aws s3control get-public-access-block --account-id "$account_id" --output json

# KMS evidence (describe-key alone omits policy/grants/rotation — collect each)
capture "$run/kms/describe-key.json"  -- aws kms describe-key --key-id "$KMS_KEY_ARN" --output json
capture "$run/kms/key-policy.json"    -- aws kms get-key-policy --key-id "$KMS_KEY_ARN" --policy-name default --output json
capture "$run/kms/rotation.json"      -- aws kms get-key-rotation-status --key-id "$KMS_KEY_ARN" --output json
capture "$run/kms/grants.json"        -- aws kms list-grants --key-id "$KMS_KEY_ARN" --output json
capture "$run/kms/tags.json"          -- aws kms list-resource-tags --key-id "$KMS_KEY_ARN" --output json

# CloudTrail evidence (management + S3 data-event selectors)
capture "$run/cloudtrail/trails.json"          -- aws cloudtrail describe-trails --include-shadow-trails --output json
capture "$run/cloudtrail/trail-status.json"    -- aws cloudtrail get-trail-status --name "$TRAIL_ARN" --output json
capture "$run/cloudtrail/event-selectors.json" -- aws cloudtrail get-event-selectors --trail-name "$TRAIL_ARN" --output json

# AWS Config evidence (recorder, rules, history, compliance)
capture "$run/config/recorders.json"       -- aws configservice describe-configuration-recorders --output json
capture "$run/config/recorder-status.json" -- aws configservice describe-configuration-recorder-status --output json
capture "$run/config/rules.json"           -- aws configservice describe-config-rules --output json
capture "$run/config/bucket-history.json"  -- aws configservice get-resource-config-history \
  --resource-type AWS::S3::Bucket --resource-id "$BUCKET" --chronological-order Reverse --limit 20 --output json
capture "$run/config/bucket-compliance.json" -- aws configservice describe-compliance-by-resource \
  --resource-type AWS::S3::Bucket --resource-id "$BUCKET" --output json

# Terraform + Git provenance
capture "$run/terraform/version.json"   -- terraform version -json
capture "$run/terraform/providers.txt"  -- terraform providers
# Refresh-only drift plan (exit 2 = drift, 1 = error, 0 = none). The saved plan
# may contain sensitive state — keep it in a restricted location.
terraform plan -refresh-only -detailed-exitcode -out="$run/terraform/drift.tfplan" \
  > "$run/terraform/drift-plan.txt" 2> "$run/terraform/drift-plan.error.txt" \
  && echo 0 > "$run/terraform/drift-exitcode.txt" \
  || echo $? > "$run/terraform/drift-exitcode.txt"
# Human-agnostic JSON the lab's Lambda evaluates (upload to PLAN_BUCKET/PLAN_KEY):
terraform show -json "$run/terraform/drift.tfplan" \
  > "$run/terraform/plan.json" 2> "$run/terraform/plan.error.txt" || true

git rev-parse HEAD                              > "$run/git/commit-sha.txt" 2>&1 || true
git status --porcelain=v1                       > "$run/git/working-tree-status.txt" 2>&1 || true
git log -1 --format=fuller --show-signature     > "$run/git/commit-details.txt" 2>&1 || true

# Integrity manifest over the whole package
find "$run" -type f ! -name "hashes.sha256" -print0 \
  | sort -z | xargs -0 sha256sum > "$run/hashes.sha256"

echo "Evidence package: $run"
echo "Drift exit code : $(cat "$run/terraform/drift-exitcode.txt")  (0=none, 2=drift, 1=error)"
echo "Next: aws s3 cp \"$run/terraform/plan.json\" \"s3://\$PLAN_BUCKET/\$PLAN_KEY\" --sse aws:kms"
