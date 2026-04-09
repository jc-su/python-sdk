#!/usr/bin/env bash
set -euo pipefail

SESSION="tfc-agentdojo-4o"
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
find "$LOG_DIR" -maxdepth 1 -type f \( -name 'adj4o-banking.log' -o -name 'adj4o-slack.log' -o -name 'adj4o-travel.log' -o -name 'adj4o-workspace.log' \) 2>/dev/null | sort
