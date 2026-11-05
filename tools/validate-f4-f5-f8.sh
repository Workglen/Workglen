#!/bin/bash
# Offline synthetic validation for F4, F5 and F8. Installs nothing, starts no
# listeners, sends no mail and does not contact external providers.
set -uo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
CARGO=${CARGO:-cargo}
PYTHON=${PYTHON:-python3}
RESULT_DIR=${RESULT_DIR:-"$ROOT/validation/f4-f5-f8-local"}
mkdir -p "$RESULT_DIR"
LOG="$RESULT_DIR/validation.log"
: > "$LOG"

if ! command -v "$CARGO" >/dev/null 2>&1; then
    echo "Cargo not found: $CARGO. Prepare the pinned Rust toolchain and cached locked dependencies first." >&2
    exit 127
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "Python not found: $PYTHON" >&2
    exit 127
fi

FORMAT_STATUS=0
FAILURES=()

run() {
    local name=$1
    local status
    shift
    printf '\n$' | tee -a "$LOG"
    printf ' %s' "$@" | tee -a "$LOG"
    printf '\n' | tee -a "$LOG"
    if "$@" 2>&1 | tee -a "$LOG"; then
        printf 'PASS: %s\n' "$name" | tee -a "$LOG"
    else
        status=$?
        printf 'FAIL: %s (exit %d)\n' "$name" "$status" | tee -a "$LOG"
        if [ "$name" = formatting ]; then
            FORMAT_STATUS=$status
        else
            FAILURES+=("$name (exit $status)")
        fi
    fi
    return 0
}

printf 'Workglen F4/F5/F8 offline validation\nHost: ' | tee -a "$LOG"
uname -a | tee -a "$LOG"
printf 'Results: %s\n' "$RESULT_DIR" | tee -a "$LOG"

run formatting "$CARGO" fmt --all -- --check --color never
run "IDNA table verification" "$PYTHON" crates/native-idna/tools/generate.py --check
run "IDNA security-boundary tests" "$CARGO" test --offline --locked -p workglen-idna --test security_boundary
run "F8 clock regression" "$CARGO" test --offline --locked datetime::clock_tests::utc_conversion_rejects_out_of_range_clocks_without_fallback -- --exact
run "F4 scanner-budget regression" "$CARGO" test --offline --locked operator_scanner_budgets_reject_oversized_input_decoding_and_parts
run "F4 budget-configuration regression" "$CARGO" test --offline --locked scanner_budget_configuration_bounds_are_enforced
run "F4 concurrency-permit regression" "$CARGO" test --offline --locked scan_permits_bound_concurrency_and_release_on_drop
run "F5 mixed-script regression" "$CARGO" test --offline --locked mixed_script_domain_check_is_opt_in_and_preserves_single_script_names
run "workspace tests" "$CARGO" test --offline --locked --workspace
run Clippy "$CARGO" clippy --offline --locked --workspace --all-targets -- -D warnings
run "release build" "$CARGO" build --offline --locked --release --workspace

if [ -d .git ]; then
    run "Git whitespace check" git diff --check
fi

printf '\nValidation summary\n' | tee -a "$LOG"
if [ "$FORMAT_STATUS" -ne 0 ]; then
    printf 'FORMAT FAILED (exit %d): cargo fmt --check reported differences; no files were changed.\n' "$FORMAT_STATUS" | tee -a "$LOG"
else
    printf 'FORMAT PASS\n' | tee -a "$LOG"
fi
if [ "${#FAILURES[@]}" -gt 0 ]; then
    printf 'OTHER FAILED CHECKS:\n' | tee -a "$LOG"
    printf '  %s\n' "${FAILURES[@]}" | tee -a "$LOG"
else
    printf 'ALL NON-FORMATTING CHECKS PASS\n' | tee -a "$LOG"
fi
printf 'This is synthetic validation, not live-provider, production-capacity or detection-efficacy evidence.\n' | tee -a "$LOG"

if [ "$FORMAT_STATUS" -ne 0 ] || [ "${#FAILURES[@]}" -gt 0 ]; then
    printf 'FAIL: offline F4/F5/F8 validation completed with failures. Log: %s\n' "$LOG" | tee -a "$LOG"
    exit 1
fi
printf 'PASS: offline F4/F5/F8 validation completed. Log: %s\n' "$LOG" | tee -a "$LOG"
