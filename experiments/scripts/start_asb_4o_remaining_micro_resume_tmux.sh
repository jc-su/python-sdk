#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/jcsu/Dev/tee-mcp"
DATA_DIR="$ROOT/mcp-sdk-fork/experiments/data"
LOG_DIR="$DATA_DIR/run_logs"
SESSION="tfc-asb-4o-rest-micro"
ATTACKS="context_ignoring combined_attack escape_characters fake_completion"

mkdir -p "$LOG_DIR"

MISSING_AGENTS="$(
python - <<'PY'
import json
from pathlib import Path
root = Path("/home/jcsu/Dev/tee-mcp/mcp-sdk-fork/experiments/data")
all_agents = [
    "academic_search_agent",
    "aerospace_engineer_agent",
    "autonomous_driving_agent",
    "ecommerce_manager_agent",
    "education_consultant_agent",
    "financial_analyst_agent",
    "legal_consultant_agent",
    "medical_advisor_agent",
    "psychological_counselor_agent",
    "system_admin_agent",
]
completed = set()
for p in root.glob("asb_real_v2_baseline_gpt-4o-2024-05-13__all__context_ignoring__combined_attack__escape_characters__fake_completion__*.json"):
    data = json.loads(p.read_text())
    if data.get("partial") is False:
        completed.update(data.get("agents") or [])
missing = [a for a in all_agents if a not in completed]
print(" ".join(missing))
PY
)"

if [[ -z "${MISSING_AGENTS}" ]]; then
  echo "No missing agents for remaining ASB variants."
  exit 0
fi

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

run_window asb4o-micro-baseline "mcp-sdk-fork/experiments/scripts/run_asb_v2_sharded.py --llm-name gpt-4o-2024-05-13 --attack-tool-set all --task-num 1 --attack-types $ATTACKS --split-attack-types --configs baseline --agents $MISSING_AGENTS"
run_window asb4o-micro-def "mcp-sdk-fork/experiments/scripts/run_asb_v2_sharded.py --llm-name gpt-4o-2024-05-13 --attack-tool-set all --task-num 1 --attack-types $ATTACKS --split-attack-types --configs trustfncall --agents $MISSING_AGENTS"

echo "tmux session: $SESSION"
echo "attach: tmux attach -t $SESSION"
echo "missing agents: $MISSING_AGENTS"
tmux list-windows -t "$SESSION"
