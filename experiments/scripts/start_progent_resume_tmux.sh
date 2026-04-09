#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/jcsu/Dev/tee-mcp"
LOG_DIR="$ROOT/mcp-sdk-fork/experiments/data/run_logs"
SESSION="tfc-progent-4o"
MODEL="gpt-4o-2024-05-13"
ATTACK="important_instructions"

mkdir -p "$LOG_DIR"

run_window() {
  local window="$1"
  shift
  local logfile="$LOG_DIR/${window}.log"
  local cmd="cd '$ROOT' && python $* 2>&1 | tee -a '$logfile'"
  if tmux list-windows -t "$SESSION" 2>/dev/null | rg -q "^[0-9]+: ${window} "; then
    echo "skip existing window: $window"
    return
  fi
  tmux new-window -t "$SESSION" -n "$window" "bash -lc \"$cmd; code=\${PIPESTATUS[0]}; echo; echo '[${window}] exit code:' \$code; exec bash\""
}

if ! tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux new-session -d -s "$SESSION" -n shell "bash -lc 'cd \"$ROOT\"; exec bash'"
fi

run_window progent-adj-manual "mcp-sdk-fork/experiments/scripts/run_progent_agentdojo.py --model $MODEL --attack $ATTACK --mode manual"
run_window progent-adj-auto "mcp-sdk-fork/experiments/scripts/run_progent_agentdojo.py --model $MODEL --attack $ATTACK --mode auto --policy-model $MODEL"
run_window progent-asb-manual "mcp-sdk-fork/experiments/scripts/run_progent_asb.py --llm-name $MODEL --mode manual"
run_window progent-asb-auto "mcp-sdk-fork/experiments/scripts/run_progent_asb.py --llm-name $MODEL --mode auto --policy-model $MODEL"

echo "tmux session: $SESSION"
echo "attach: tmux attach -t $SESSION"
tmux list-windows -t "$SESSION"
