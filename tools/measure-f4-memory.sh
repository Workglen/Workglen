#!/bin/bash
# Explicit synthetic release-mode concurrent-scanner RSS probe. No live service,
# external provider, mail, host swap or system configuration is used or changed.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
CARGO=${CARGO:-cargo}
RESULT_DIR=${RESULT_DIR:-"$ROOT/validation/f4-f5-f8-local"}
mkdir -p "$RESULT_DIR"
LOG="$RESULT_DIR/memory-probe.log"
: > "$LOG"

if ! command -v "$CARGO" >/dev/null 2>&1; then
    echo "Cargo not found: $CARGO" >&2
    exit 127
fi
if [ ! -x /usr/bin/time ]; then
    echo "/usr/bin/time is required for peak RSS measurement" >&2
    exit 127
fi

case $(uname -s) in
    Darwin) TIME_FLAG=-l ;;
    Linux) TIME_FLAG=-v ;;
    *) echo "This probe supports macOS and Linux" >&2; exit 2 ;;
esac

run() {
    printf '\n$' | tee -a "$LOG"
    printf ' %s' "$@" | tee -a "$LOG"
    printf '\n' | tee -a "$LOG"
    "$@" 2>&1 | tee -a "$LOG"
}

printf 'Synthetic F4 concurrent-scanner memory probe\nHost: ' | tee -a "$LOG"
uname -a | tee -a "$LOG"
printf 'Two overlapping scans, three iterations each, 4 MiB binary attachment per message.\n' | tee -a "$LOG"
printf 'The release harness is compiled before the timed run.\n' | tee -a "$LOG"
run "$CARGO" test --offline --locked --release concurrent_scanner_memory_probe --no-run
run /usr/bin/time "$TIME_FLAG" "$CARGO" test --offline --locked --release concurrent_scanner_memory_probe -- --ignored --nocapture --test-threads=1

printf '\nReview the peak RSS/maximum resident set size above. Log: %s\n' "$LOG" | tee -a "$LOG"
printf 'Scope: synthetic test-process evidence only; not gateway/service peak RSS, production capacity, leak detection or detection efficacy.\n' | tee -a "$LOG"
printf 'No swap setting is recommended or changed by this probe.\n' | tee -a "$LOG"
