#!/usr/bin/env bash
set -euo pipefail

BUNDLE="$(cd "$(dirname "$0")" && pwd)"
INPUT="$BUNDLE/payload.java"
TIMEOUT_S="${TIMEOUT_S:-20}"
WAIT_REPORT_S="${WAIT_REPORT_S:-8}"
DIAG_DIR="$HOME/Library/Logs/DiagnosticReports"
OUT_ROOT="${OUT_ROOT:-$BUNDLE/evidence}"
RUN_ID="${RUN_ID:-java_live_$(date +%Y%m%d_%H%M%S)}"
OUT_DIR="$OUT_ROOT/$RUN_ID"

echo "Demo: JavaFunctionScanner Stack Overflow"
echo "Affected software: BBEdit 15.5.5 (build 430000124), live process"
echo

if [[ ! -f "$INPUT" ]]; then
  echo "[!] Missing reproducer: $INPUT"
  exit 1
fi

if ! pgrep -x "BBEdit" >/dev/null 2>&1; then
  echo "[!] BBEdit is not running. Start BBEdit first, then re-run this script."
  exit 1
fi

mkdir -p "$OUT_DIR"
before_pid="$(pgrep -x "BBEdit" | head -n 1)"
tmp_java_base="$(mktemp "/tmp/bbedit_live_java_crash.XXXXXX")"
tmp_java="${tmp_java_base}.java"
cp "$INPUT" "$tmp_java"
shasum -a 256 "$tmp_java" > "$OUT_DIR/input.sha256"

start_epoch="$(date +%s)"
{
  echo "run_id=$RUN_ID"
  echo "start_epoch=$start_epoch"
  echo "bbedit_pid_before=$before_pid"
  echo "input_path=$tmp_java"
  echo "input_source=$INPUT"
  echo "timeout_s=$TIMEOUT_S"
} > "$OUT_DIR/run.meta"

echo "[*] Live BBEdit PID before trigger: $before_pid"
echo "[*] Opening crafted .java file in running BBEdit: $tmp_java"
open -a "BBEdit" "$tmp_java"

set +e
for _ in $(seq 1 "$TIMEOUT_S"); do
  sleep 1
  if ! ps -p "$before_pid" >/dev/null 2>&1; then
    break
  fi
done
set -e

crashed=0
if ! ps -p "$before_pid" >/dev/null 2>&1; then
  crashed=1
fi

echo "[*] Waiting up to ${WAIT_REPORT_S}s for crash report..."
sleep "$WAIT_REPORT_S"

report_candidate=""
if [[ -d "$DIAG_DIR" ]]; then
  while IFS= read -r f; do
    mtime="$(stat -f %m "$f" 2>/dev/null || echo 0)"
    if [[ "$mtime" -ge "$start_epoch" ]]; then
      report_candidate="$f"
      break
    fi
  done < <(ls -1t "$DIAG_DIR"/BBEdit*.ips "$DIAG_DIR"/BBEdit*.crash 2>/dev/null || true)
fi

symbol_match=0
if [[ -n "$report_candidate" ]]; then
  cp "$report_candidate" "$OUT_DIR/"
  if grep -Eiq "JavaFunctionScanner|JavaMachO|scanInterface" "$report_candidate"; then
    symbol_match=1
  fi
fi

{
  echo "bbedit_crashed=$crashed"
  echo "report_candidate=${report_candidate:-none}"
  echo "report_symbol_match=$symbol_match"
} >> "$OUT_DIR/run.meta"

echo
if [[ "$crashed" -eq 1 && "$symbol_match" -eq 1 ]]; then
  echo "[+] Reproduced with strong evidence:"
  echo "    - live BBEdit PID exited"
  echo "    - fresh DiagnosticReport matched Java scanner symbols"
  echo "    Evidence: $OUT_DIR"
  exit 0
fi

if [[ "$crashed" -eq 1 ]]; then
  echo "[!] BBEdit PID exited, but no matching Java crash report was found."
  echo "    Evidence: $OUT_DIR"
  exit 1
fi

echo "[!] BBEdit PID $before_pid is still alive after ${TIMEOUT_S}s."
echo "    No live-process crash observed. Evidence: $OUT_DIR"
exit 1
