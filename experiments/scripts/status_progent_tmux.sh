#!/usr/bin/env bash
set -euo pipefail

SESSION="tfc-progent-4o"
LOG_DIR="/home/jcsu/Dev/tee-mcp/mcp-sdk-fork/experiments/data/run_logs"

if ! tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "no tmux session: $SESSION"
  exit 1
fi

echo "session: $SESSION"
tmux list-windows -t "$SESSION"
echo
for log in "$LOG_DIR"/progent-*.log; do
  [ -f "$log" ] || continue
  echo "===== $(basename "$log") ====="
  tail -n 20 "$log"
  echo
done
