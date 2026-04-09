#!/usr/bin/env bash
set -euo pipefail

SESSION="tfc-asb-4o"
LOG_DIR="/home/jcsu/Dev/tee-mcp/mcp-sdk-fork/experiments/data/run_logs"

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "tmux session: $SESSION"
  tmux list-windows -t "$SESSION"
  echo
  tmux list-panes -t "$SESSION" -F '#{window_name}:#{pane_current_command}'
else
  echo "tmux session not found: $SESSION"
fi

echo
echo "recent logs:"
find "$LOG_DIR" -maxdepth 1 -type f \( -name 'asb4o-baseline.log' -o -name 'asb4o-def.log' \) 2>/dev/null | sort
