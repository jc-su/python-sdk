#!/usr/bin/env bash
set -euo pipefail

# Launch Progent experiments in tmux — survives SSH disconnect
#
# Runs:
#   1. Progent AgentDojo (manual, gpt-4o-mini, important_instructions) → all 4 suites
#   2. Progent ASB (manual, gpt-4o-2024-05-13, OPI 5 types) → all 10 agents
#
# Results saved to:
#   experiments/data/progent_agentdojo_manual_*.json
#   experiments/data/progent_asb_manual_*.json
#
# Monitor: tmux attach -t tfc-progent
# Status:  bash experiments/scripts/start_progent_tmux.sh --status

ROOT="/home/jcsu/Dev/tee-mcp"
SCRIPTS="$ROOT/mcp-sdk-fork/experiments/scripts"
DATA="$ROOT/mcp-sdk-fork/experiments/data"
LOG_DIR="$DATA/run_logs"
SESSION="tfc-progent"

mkdir -p "$LOG_DIR"

# Load API key
export OPENAI_API_KEY="$(grep OPENAI_API_KEY "$ROOT/mcp-sdk-fork/experiments/.env" | cut -d= -f2)"

if [[ "${1:-}" == "--status" ]]; then
    echo "=== tmux session: $SESSION ==="
    tmux list-windows -t "$SESSION" 2>/dev/null || echo "No session found"
    echo
    echo "=== Result files ==="
    ls -lh "$DATA"/progent_agentdojo_*.json "$DATA"/progent_asb_*.json 2>/dev/null || echo "No results yet"
    echo
    echo "=== Running processes ==="
    ps aux | grep "run_progent" | grep -v grep || echo "None"
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

# Create session if needed
if ! tmux has-session -t "$SESSION" 2>/dev/null; then
    tmux new-session -d -s "$SESSION" -n shell "bash -lc 'cd \"$ROOT/mcp-sdk-fork\"; exec bash'"
fi

# =====================================================================
# AgentDojo: Progent manual policies, gpt-4o-mini (fast, 200K TPM)
# All 4 suites, important_instructions attack
# =====================================================================
run_window progent-adj-mini \
    "python experiments/scripts/run_progent_agentdojo.py \
        --model gpt-4o-mini-2024-07-18 \
        --mode manual \
        --attack important_instructions \
        --suites banking workspace slack travel"

# =====================================================================
# ASB: Progent manual policies, gpt-4o-2024-05-13 (same as our TrustFnCall)
# OPI with all 5 attack types
# =====================================================================
run_window progent-asb-4o \
    "python experiments/scripts/run_progent_asb.py \
        --llm-name gpt-4o-2024-05-13 \
        --mode manual \
        --attack-types naive context_ignoring combined_attack escape_characters fake_completion \
        --attack-tool-set all \
        --task-num 1"

echo
echo "tmux session: $SESSION"
echo "Attach: tmux attach -t $SESSION"
echo "Status: bash $0 --status"
tmux list-windows -t "$SESSION"
