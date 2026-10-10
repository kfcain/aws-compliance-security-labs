#!/usr/bin/env bash
# Evaluate labs 16 and 17 Conftest policies and fail when a run evaluates 0 tests.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"

if ! command -v conftest >/dev/null || ! command -v opa >/dev/null; then
  echo "FAIL: conftest and opa must be on PATH" >&2
  exit 1
fi

# Strip ANSI so a green "0 tests" line cannot hide in color codes.
strip() { sed -E 's/\x1B\[[0-9;]*[mK]//g'; }

run_conftest() {
  local ns="$1"
  local policy="$2"
  local input="$3"
  local expect="$4" # fail | pass
  local label="$5"
  local out rc
  set +e
  out="$(conftest test "$input" --policy "$policy" --namespace "$ns" --no-color 2>&1)"
  rc=$?
  set -e
  printf '%s\n' "$out"
  if printf '%s\n' "$out" | strip | grep -Eq '(^| )0 tests'; then
    echo "FAIL: ${label} evaluated 0 tests (namespace ${ns})" >&2
    exit 1
  fi
  if [[ "$expect" == "fail" ]]; then
    if [[ "$rc" -eq 0 ]]; then
      echo "FAIL: ${label} passed; a violation was required" >&2
      exit 1
    fi
    if ! printf '%s\n' "$out" | grep -q "$label"; then
      echo "FAIL: ${label} was not in the Conftest output" >&2
      exit 1
    fi
    if printf '%s\n' "$out" | strip | grep -Eq '"msg" field must be present|^Error:'; then
      echo "FAIL: ${label} hit a Conftest error instead of a deny message" >&2
      exit 1
    fi
  elif [[ "$rc" -ne 0 ]]; then
    echo "FAIL: ${label} exited ${rc}; a clean input was required" >&2
    exit 1
  fi
}

drift_policy="${root}/labs/16-terraform-drift-detection/governance/policy"
drift_fixtures="${root}/labs/16-terraform-drift-detection/governance/fixtures"
dr_policy="${root}/labs/17-terraform-dr-readiness/governance/policy"
dr_fixtures="${root}/labs/17-terraform-dr-readiness/governance/fixtures"

run_conftest tfdrift.drift "$drift_policy" \
  "${drift_fixtures}/bad-s3-cui-drift.json" fail "S3-CUI-DRIFT-001"
run_conftest tfdrift.drift "$drift_policy" \
  "${drift_fixtures}/good-plan.json" pass "clean drift plan"
run_conftest tfdrift.drift "$drift_policy" \
  "${drift_fixtures}/bad-drift-evidence.json" fail "S3-CUI-DRIFT-002"
run_conftest tfdrift.drift "$drift_policy" \
  "${drift_fixtures}/bad-unsealed.json" fail "S3-CUI-DRIFT-003"
run_conftest tfdr.readiness "$dr_policy" \
  "${dr_fixtures}/bad-state.json" fail "DR-STATE-001"
run_conftest tfdr.readiness "$dr_policy" \
  "${dr_fixtures}/bad-ready.json" fail "DR-READY-003"
run_conftest tfdr.readiness "$dr_policy" \
  "${dr_fixtures}/bad-prov.json" fail "DR-PROV-004"
run_conftest tfdr.readiness "$dr_policy" \
  "${dr_fixtures}/bad-rpo.json" fail "DR-RPO-002"
run_conftest tfdr.readiness "$dr_policy" \
  "${dr_fixtures}/good-evidence.json" pass "clean DR evidence"

# --all-namespaces must report the violation, not error on a non-string msg.
# Fixtures live outside the policy directory so OPA does not merge them as data.
set +e
all_out="$(conftest test "${drift_fixtures}/bad-s3-cui-drift.json" \
  --policy "$drift_policy" --all-namespaces --no-color 2>&1)"
all_rc=$?
set -e
printf '%s\n' "$all_out"
if printf '%s\n' "$all_out" | strip | grep -Eq '(^| )0 tests|"msg" field must be present'; then
  echo "FAIL: --all-namespaces did not evaluate the drift policy" >&2
  exit 1
fi
if ! printf '%s\n' "$all_out" | grep -q 'S3-CUI-DRIFT-001'; then
  echo "FAIL: --all-namespaces did not report S3-CUI-DRIFT-001 (exit ${all_rc})" >&2
  exit 1
fi

set +e
opa_out="$(opa test -v "$drift_policy" "$dr_policy" 2>&1)"
opa_rc=$?
set -e
printf '%s\n' "$opa_out"
if [[ "$opa_rc" -ne 0 ]] || printf '%s\n' "$opa_out" | grep -Eq '^FAIL:'; then
  echo "FAIL: opa test reported a failing case" >&2
  exit 1
fi
if ! printf '%s\n' "$opa_out" | grep -Eq 'PASS: [1-9][0-9]*/[1-9]'; then
  echo "FAIL: opa test did not report a non-zero pass count" >&2
  exit 1
fi

echo "policy gate OK"
