#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/jcsu/Dev/tee-mcp"
EXP_ROOT="$ROOT/mcp-sdk-fork/experiments"
LOG_DIR="$EXP_ROOT/data/run_logs"
SESSION="tfc-eval"

mkdir -p "$LOG_DIR"

run_window() {
  local window="$1"
  shift
  local logfile="$LOG_DIR/${window}.log"
  local cmd="cd '$ROOT' && python $* 2>&1 | tee -a '$logfile'"
  if tmux list-windows -t "$SESSION" 2>/dev/null | rg -q "^.*:${window} "; then
    echo "skip existing window: $window"
    return
  fi
  tmux new-window -t "$SESSION" -n "$window" "bash -lc \"$cmd; code=\${PIPESTATUS[0]}; echo; echo '[${window}] exit code:' \$code; exec bash\""
}

if ! tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux new-session -d -s "$SESSION" -n shell "bash -lc 'cd \"$ROOT\"; exec bash'"
fi

run_window adj-banking "mcp-sdk-fork/experiments/scripts/run_agentdojo_v2_sharded.py --model gpt-4o-2024-05-13 --attacks important_instructions --configs trustfncall_trace_args --suites banking --tasks-per-shard 1"
run_window adj-slack "mcp-sdk-fork/experiments/scripts/run_agentdojo_v2_sharded.py --model gpt-4o-2024-05-13 --attacks important_instructions --configs trustfncall_trace_args --suites slack --tasks-per-shard 1"
run_window adj-travel "mcp-sdk-fork/experiments/scripts/run_agentdojo_v2_sharded.py --model gpt-4o-2024-05-13 --attacks important_instructions --configs trustfncall_trace_args --suites travel --tasks-per-shard 1"
run_window adj-workspace "mcp-sdk-fork/experiments/scripts/run_agentdojo_v2_sharded.py --model gpt-4o-2024-05-13 --attacks important_instructions --configs trustfncall_trace_args --suites workspace --tasks-per-shard 1"
run_window asb-baseline "mcp-sdk-fork/experiments/scripts/run_asb_v2_sharded.py --llm-name gpt-4o-2024-05-13 --attack-tool-set all --task-num 1 --attack-types naive --configs baseline"
run_window asb-def "mcp-sdk-fork/experiments/scripts/run_asb_v2_sharded.py --llm-name gpt-4o-2024-05-13 --attack-tool-set all --task-num 1 --attack-types naive --configs trustfncall"
run_window progent-manual "mcp-sdk-fork/experiments/scripts/run_progent_agentdojo.py --mode manual --model gpt-4o-2024-05-13 --policy-model gpt-4o-2024-05-13"
run_window melon "mcp-sdk-fork/experiments/scripts/run_melon_agentdojo.py --model gpt-4o-2024-05-13 --attack important_instructions"

echo "tmux session: $SESSION"
echo "attach: tmux attach -t $SESSION"
echo "windows:"
tmux list-windows -t "$SESSION"
