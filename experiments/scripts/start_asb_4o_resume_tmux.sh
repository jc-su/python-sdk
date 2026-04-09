#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/jcsu/Dev/tee-mcp"
LOG_DIR="$ROOT/mcp-sdk-fork/experiments/data/run_logs"
SESSION="tfc-asb-4o"

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

# Resume only; completed agent shards are skipped by run_asb_v2_sharded.py.
run_window asb4o-baseline "mcp-sdk-fork/experiments/scripts/run_asb_v2_sharded.py --llm-name gpt-4o-2024-05-13 --attack-tool-set all --task-num 1 --attack-types naive --configs baseline"
run_window asb4o-def "mcp-sdk-fork/experiments/scripts/run_asb_v2_sharded.py --llm-name gpt-4o-2024-05-13 --attack-tool-set all --task-num 1 --attack-types naive --configs trustfncall"

echo "tmux session: $SESSION"
echo "attach: tmux attach -t $SESSION"
tmux list-windows -t "$SESSION"
