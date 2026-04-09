# TrustFnCall Eval V2 Notes

This note separates what is already fair to compare from what is not.

## Fair Today

- Static-analysis classification quality:
  - `experiments/scripts/exp1_pysa_accuracy.py`
  - This is a real offline analysis result and fair to compare as a classifier.
- System overhead:
  - `experiments/scripts/bench_system.py`
  - Latency / throughput / memory are real, except `bench_pysa_time()` is still replayed rather than freshly measured.
- Real AgentDojo runtime evaluation:
  - `experiments/scripts/run_agentdojo_v2.py`
  - This is the correct comparison path for AgentArmor-style tables.
- Real ASB runtime evaluation:
  - `experiments/scripts/run_asb_v2.py`
  - This is the correct comparison path for AgentArmor-style ASB tables.

## Not Fair To Compare Directly

- `experiments/scripts/full_evaluation.py`
  - This is static policy analysis, not an end-to-end LLM benchmark.
  - It should be reported as worst-case policy coverage, not as a direct replacement for AgentArmor / MELON numbers.
- `experiments/scripts/run_asb.py`
  - This is a custom OpenAI tool-calling harness over ASB data.
  - It is not the original ASB runtime, so its results should not go into the main comparison table.

## AgentDojo v2 Design

TrustFnCall is enforced inside the runtime loop rather than as a one-shot prefilter.

- Old issue:
  - defense sat outside `ToolsExecutionLoop`
  - later tool calls in the same scenario could bypass the defense
- v2 fix:
  - hook authorization in the executor inside the loop
  - this mirrors the runtime-hooking style used by AgentArmor

Metrics:

- `ASR`: attacked scenarios where the injection task succeeds
- `UA`: attacked scenarios where the benign task still succeeds
- `UAR_no_atk`: benign scenarios without injection where the user task succeeds
- `TPR_labeled`: blocked malicious calls / labeled malicious calls
- `FPR_benign`: blocked benign calls / benign calls in no-attack runs

Trace labeling:

- benign call:
  - matches the benign task ground-truth call
- malicious call:
  - matches the injection-task ground-truth call
- ambiguous:
  - matches both
- unlabeled:
  - matches neither

`TPR_labeled` is reported only on the labeled malicious subset.

## ASB Real Hook Plan

The real hook points are in the ASB runtime itself:

- benign agent:
  - `ASB/pyopenagi/agents/react_agent.py`
  - method `call_tools()`
- attacked agent:
  - `ASB/pyopenagi/agents/react_agent_attack.py`
  - method `call_tools()`
- evaluation loop:
  - `ASB/main_attacker.py`

To make ASB fair:

1. Patch or subclass the ASB agent classes to authorize each tool invocation before `function_to_call.run(...)`.
2. Record each attempted tool call with allow / block decision.
3. Reuse ASB's own success criteria from `main_attacker.py`:
   - attack success via `check_attack_success(...)`
   - original task success via `check_original_success(...)`
4. Report:
   - `ASR`
   - `UAR_no_atk`
   - `TPR`
   - `FPR`

This is now implemented in:

- `experiments/scripts/run_asb_v2.py`

## Recommended Paper Positioning

- Main comparison table:
  - use `run_agentdojo_v2.py`
  - later use a real ASB runtime hook
- Separate analysis section:
  - keep static policy-analysis results
  - explicitly label them as worst-case policy coverage under full LLM compliance
