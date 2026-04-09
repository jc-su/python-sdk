#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/jcsu/Dev/tee-mcp"
EXP_ROOT="$ROOT/mcp-sdk-fork/experiments"
SESSION="tfc-eval"

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "tmux session: $SESSION"
  tmux list-windows -t "$SESSION"
else
  echo "tmux session not found: $SESSION"
fi

echo
echo "recent logs:"
find "$EXP_ROOT/data/run_logs" -maxdepth 1 -type f -printf "%TY-%Tm-%Td %TH:%TM:%TS %p\n" 2>/dev/null | sort -r | head -n 20
