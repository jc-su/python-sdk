#!/usr/bin/env bash
set -euo pipefail

# Launch SOTA TrustFnCall experiments in tmux — survives SSH disconnect
#
# Model: gpt-4o-2024-08-06 (same as Progent paper)
# Attack: important_instructions
# Configs:
#   - baseline (no defense)
#   - trustfncall_manual (hand-crafted per-suite, like Progent)
#   - trustfncall_trace_args (automated: Pysa categories + preflight trace)
#
# Runs sharded (1 user task per shard) with resume.
#
# Monitor: tmux attach -t tfc-sota
# Status:  bash experiments/scripts/start_sota_tmux.sh --status

ROOT="/home/jcsu/Dev/tee-mcp"
SCRIPTS="$ROOT/mcp-sdk-fork/experiments/scripts"
DATA="$ROOT/mcp-sdk-fork/experiments/data"
LOG_DIR="$DATA/run_logs"
SESSION="tfc-sota"
MODEL="gpt-4o-2024-08-06"

mkdir -p "$LOG_DIR"

export OPENAI_API_KEY="$(grep OPENAI_API_KEY "$ROOT/mcp-sdk-fork/experiments/.env" | cut -d= -f2)"

if [[ "${1:-}" == "--status" ]]; then
    echo "=== tmux session: $SESSION ==="
    tmux list-windows -t "$SESSION" 2>/dev/null || echo "No session found"
    echo
    echo "=== Completed shards ==="
    python3 -c "
from pathlib import Path
import json
root = Path('$DATA')
for config in ['baseline', 'trustfncall_manual', 'trustfncall_trace_args']:
    files = list(root.glob(f'agentdojo_matrix_v2_${MODEL}_important_instructions__{config}__*.json'))
    complete = sum(1 for f in files if json.loads(f.read_text()).get('partial') is False)
    print(f'  {config}: {complete}/{len(files)} shards complete')
"
    echo
    echo "=== Running processes ==="
    ps aux | grep "run_agentdojo_v2" | grep -v grep | wc -l
    exit 0
fi

run_window() {
    local window="$1"
    shift
    local logfile="$LOG_DIR/${window}.log"
    local cmd="cd '$ROOT/mcp-sdk-fork' && $* 2>&1 | tee -a '$logfile'"
    if tmux list-windows -t "$SESSION" 2>/dev/null | grep -q "${window}"; then
        echo "SKIP existing window: $window"
        return
    fi
    tmux new-window -t "$SESSION" -n "$window" \
        "bash -lc \"export OPENAI_API_KEY='$OPENAI_API_KEY'; $cmd; code=\${PIPESTATUS[0]}; echo; echo '[${window}] exit code:' \$code; exec bash\""
    echo "STARTED: $window"
}

if ! tmux has-session -t "$SESSION" 2>/dev/null; then
    tmux new-session -d -s "$SESSION" -n shell "bash -lc 'cd \"$ROOT/mcp-sdk-fork\"; exec bash'"
fi

# =====================================================================
# 1. Baseline (no defense) — sharded, 1 task per shard, resume
# =====================================================================
run_window sota-baseline \
    "python $SCRIPTS/run_agentdojo_v2_sharded.py \
        --model $MODEL \
        --attacks important_instructions \
        --configs baseline \
        --suites banking workspace slack travel \
        --tasks-per-shard 1"

# =====================================================================
# 2. TrustFnCall-Manual (hand-crafted per-suite policies, like Progent)
# =====================================================================
run_window sota-manual \
    "python $SCRIPTS/run_agentdojo_v2_sharded.py \
        --model $MODEL \
        --attacks important_instructions \
        --configs trustfncall_manual \
        --suites banking workspace slack travel \
        --tasks-per-shard 1"

# =====================================================================
# 3. TrustFnCall-Trace (automated: Pysa categories + preflight trace)
# =====================================================================
run_window sota-trace \
    "python $SCRIPTS/run_agentdojo_v2_sharded.py \
        --model $MODEL \
        --attacks important_instructions \
        --configs trustfncall_trace_args \
        --suites banking workspace slack travel \
        --tasks-per-shard 1"

echo
echo "tmux session: $SESSION"
echo "Attach: tmux attach -t $SESSION"
echo "Status: bash $0 --status"
tmux list-windows -t "$SESSION"
