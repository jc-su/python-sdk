#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/jcsu/Dev/tee-mcp"
LOG_DIR="$ROOT/mcp-sdk-fork/experiments/data/run_logs"
SESSION="tfc-agentdojo-4o"

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

run_window adj4o-banking "mcp-sdk-fork/experiments/scripts/run_agentdojo_v2_sharded.py --model gpt-4o-2024-05-13 --attacks important_instructions --configs trustfncall_trace_args --suites banking --tasks-per-shard 1"
run_window adj4o-slack "mcp-sdk-fork/experiments/scripts/run_agentdojo_v2_sharded.py --model gpt-4o-2024-05-13 --attacks important_instructions --configs trustfncall_trace_args --suites slack --tasks-per-shard 1"
run_window adj4o-travel "mcp-sdk-fork/experiments/scripts/run_agentdojo_v2_sharded.py --model gpt-4o-2024-05-13 --attacks important_instructions --configs trustfncall_trace_args --suites travel --tasks-per-shard 1"
run_window adj4o-workspace "mcp-sdk-fork/experiments/scripts/run_agentdojo_v2_sharded.py --model gpt-4o-2024-05-13 --attacks important_instructions --configs trustfncall_trace_args --suites workspace --tasks-per-shard 1"

echo "tmux session: $SESSION"
echo "attach: tmux attach -t $SESSION"
tmux list-windows -t "$SESSION"
