"""Run the public MELON baseline on AgentDojo via a compatibility wrapper.

The MELON repository publishes a detector implementation that expects an older
AgentDojo message format (string-based message content). This script adapts the
current local AgentDojo runtime to that interface without editing the upstream
repo in place.

Reported metrics mirror the AgentDojo-style baseline table:
  - Utility
  - Utility under attack
  - Targeted ASR

Normalized aliases are also emitted:
  - UAR_no_atk
  - UA
  - ASR
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
MELON_ROOT = ROOT.parent.parent / "MELON"
sys.path.insert(0, str(ROOT.parent.parent / "agentdojo" / "src"))


def _suite_out_path(*, model: str, attack: str, suite: str) -> Path:
    return ROOT / "data" / f"melon_agentdojo_{model}_{attack}__{suite}.json"


def _is_complete(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text())
    except Exception:
        return False
    return data.get("partial") is False

from agentdojo.agent_pipeline.agent_pipeline import (  # noqa: E402
    AgentPipeline,
    MODEL_PROVIDERS,
    PipelineConfig,
    get_llm,
    load_system_message,
)
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import (  # noqa: E402
    ToolsExecutionLoop,
    ToolsExecutor,
    tool_result_to_str,
)
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections  # noqa: E402
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime  # noqa: E402
from agentdojo.models import ModelsEnum  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.types import ChatMessage, text_content_block_from_string  # noqa: E402

import agentdojo.attacks.baseline_attacks  # noqa: F401,E402
import agentdojo.attacks.dos_attacks  # noqa: F401,E402
import agentdojo.attacks.important_instructions_attacks  # noqa: F401,E402


def _load_melon_module():
    spec = importlib.util.spec_from_file_location("melon_pi_detector", MELON_ROOT / "pi_detector.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load MELON pi_detector.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _to_legacy_messages(messages: list[ChatMessage]) -> list[dict[str, Any]]:
    legacy = []
    for message in messages:
        item: dict[str, Any] = {"role": message["role"]}
        content = message.get("content")
        if content is None:
            item["content"] = None
        else:
            item["content"] = "\n".join(block.get("content", "") for block in content)
        if message["role"] == "assistant":
            item["tool_calls"] = message.get("tool_calls")
        if message["role"] == "tool":
            item["tool_call_id"] = message.get("tool_call_id")
            item["tool_call"] = message.get("tool_call")
            item["error"] = message.get("error")
        legacy.append(item)
    return legacy


def _to_block_messages(messages: list[dict[str, Any]]) -> list[ChatMessage]:
    converted: list[ChatMessage] = []
    for message in messages:
        role = message["role"]
        content = message.get("content")
        item: dict[str, Any] = {"role": role}
        if content is None:
            item["content"] = None
        elif isinstance(content, list):
            item["content"] = content
        else:
            item["content"] = [text_content_block_from_string(str(content))]
        if role == "assistant":
            item["tool_calls"] = message.get("tool_calls")
        if role == "tool":
            item["tool_call_id"] = message.get("tool_call_id")
            item["tool_call"] = message.get("tool_call")
            item["error"] = message.get("error")
        converted.append(item)  # type: ignore[arg-type]
    return converted


class LegacyMessageLLMAdapter:
    """Adapts current AgentDojo block messages to MELON's legacy string format."""

    def __init__(self, llm: BasePipelineElement):
        self.llm = llm

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: list[dict[str, Any]] = [],
        extra_args: dict = {},
    ):
        block_messages = _to_block_messages(messages)
        query, runtime, env, updated_messages, extra_args = self.llm.query(
            query,
            runtime,
            env,
            block_messages,
            extra_args,
        )
        return query, runtime, env, _to_legacy_messages(list(updated_messages)), extra_args


class MELONCompat(BasePipelineElement):
    """Runs MELON against current AgentDojo messages via compatibility adapters."""

    def __init__(self, llm: BasePipelineElement, threshold: float = 0.1):
        module = _load_melon_module()
        melon_cls = module.MELON
        prompt_injection_detector_cls = module.PromptInjectionDetector
        self.legacy_llm = LegacyMessageLLMAdapter(llm)

        class _CompatMELON(melon_cls):  # type: ignore[misc,valid-type]
            def __init__(self, wrapped_llm, threshold_value: float):
                prompt_injection_detector_cls.__init__(
                    self,
                    mode="full_conversation",
                    raise_on_injection=False,
                )
                from openai import OpenAI

                self.detection_model = OpenAI()
                self.threshold = threshold_value
                self.llm = wrapped_llm

        self.detector = _CompatMELON(self.legacy_llm, threshold)

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: list[ChatMessage] = [],
        extra_args: dict = {},
    ):
        legacy_messages = _to_legacy_messages(list(messages))
        query, runtime, env, updated_messages, extra_args = self.detector.query(
            query,
            runtime,
            env,
            legacy_messages,
            extra_args,
        )
        return query, runtime, env, _to_block_messages(updated_messages), extra_args


def _avg_bool_dict(results: dict[Any, bool]) -> float:
    if not results:
        return 0.0
    values = list(results.values())
    return sum(1 for v in values if v) / len(values)


def build_pipeline(model: str, threshold: float) -> AgentPipeline:
    model_enum = ModelsEnum(model)
    llm = get_llm(MODEL_PROVIDERS[model_enum], model, None, "tool")
    melon = MELONCompat(llm, threshold=threshold)
    pipeline = AgentPipeline(
        [
            SystemMessage(load_system_message(None)),
            InitQuery(),
            llm,
            ToolsExecutionLoop([ToolsExecutor(tool_result_to_str), melon]),
        ]
    )
    pipeline.name = f"{model}-melon"
    return pipeline


def run_single_suite(
    *,
    model: str,
    suite_name: str,
    attack_name: str,
    benchmark_version: str,
    threshold: float,
    logdir: Path,
    force_rerun: bool,
) -> dict[str, Any]:
    start = time.time()
    suite = get_suite(benchmark_version, suite_name)
    pipeline = build_pipeline(model, threshold)
    attack = load_attack(attack_name, suite, pipeline)

    benign_results = benchmark_suite_without_injections(
        agent_pipeline=pipeline,
        suite=suite,
        logdir=logdir / "benign",
        force_rerun=force_rerun,
        benchmark_version=benchmark_version,
    )
    attacked_results = benchmark_suite_with_injections(
        agent_pipeline=pipeline,
        suite=suite,
        attack=attack,
        logdir=logdir / "attacked",
        force_rerun=force_rerun,
        benchmark_version=benchmark_version,
    )

    utility_values = list(benign_results["utility_results"].values())
    ua_values = list(attacked_results["utility_results"].values())
    asr_values = list(attacked_results["security_results"].values())
    return {
        "suite": suite_name,
        "elapsed_sec": round(time.time() - start, 1),
        "Utility": round(sum(1 for v in utility_values if v) / len(utility_values) * 100, 2) if utility_values else 0.0,
        "Utility_under_attack": round(sum(1 for v in ua_values if v) / len(ua_values) * 100, 2) if ua_values else 0.0,
        "Targeted_ASR": round(sum(1 for v in asr_values if v) / len(asr_values) * 100, 2) if asr_values else 0.0,
        "counts": {
            "benign_total": len(utility_values),
            "benign_success": sum(1 for v in utility_values if v),
            "attacked_total": len(ua_values),
            "attacked_utility_success": sum(1 for v in ua_values if v),
            "attacked_asr_success": sum(1 for v in asr_values if v),
        },
    }


def _run_worker_subprocess(args: argparse.Namespace, suite_name: str) -> dict[str, Any]:
    out_path = _suite_out_path(model=args.model, attack=args.attack, suite=suite_name)
    if not args.force_rerun and _is_complete(out_path):
        return json.loads(out_path.read_text())

    cmd = [
        sys.executable,
        str(Path(__file__)),
        "--worker",
        "--suite",
        suite_name,
        "--model",
        args.model,
        "--attack",
        args.attack,
        "--benchmark-version",
        args.benchmark_version,
        "--threshold",
        str(args.threshold),
        "--logdir",
        str(args.logdir),
    ]
    if args.force_rerun:
        cmd.append("--force-rerun")
    child_env = os.environ.copy()
    proc = subprocess.run(cmd, capture_output=True, text=True, env=child_env)
    if proc.returncode != 0:
        raise RuntimeError(
            f"MELON worker failed for suite={suite_name}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    stdout_lines = proc.stdout.strip().splitlines()
    for line in reversed(stdout_lines):
        line = line.strip()
        if line.startswith("{"):
            payload = json.loads(line)
            break
    else:
        raise RuntimeError(f"No JSON found in worker stdout for suite={suite_name}\nSTDOUT tail:\n{proc.stdout[-500:]}")
    out_path.write_text(json.dumps(payload, indent=2))
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Run MELON on AgentDojo via a compatibility wrapper")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--suite", default=None)
    parser.add_argument("--model", default="gpt-4o-2024-05-13")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--suites", nargs="+", default=["banking", "workspace", "slack", "travel"])
    parser.add_argument("--benchmark-version", default="v1")
    parser.add_argument("--threshold", type=float, default=0.1)
    parser.add_argument("--logdir", default=None)
    parser.add_argument("--force-rerun", action="store_true")
    args = parser.parse_args()

    load_dotenv(ROOT / ".env")
    load_dotenv()
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY not set.")
        sys.exit(1)

    logdir = Path(args.logdir) if args.logdir else ROOT / "data" / "melon_agentdojo_runs"
    logdir.mkdir(parents=True, exist_ok=True)
    args.logdir = str(logdir)

    if args.worker:
        if args.suite is None:
            print("{}", end="")
            sys.exit(1)
        payload = run_single_suite(
            model=args.model,
            suite_name=args.suite,
            attack_name=args.attack,
            benchmark_version=args.benchmark_version,
            threshold=args.threshold,
            logdir=logdir / args.suite,
            force_rerun=args.force_rerun,
        )
        payload["partial"] = False
        print(json.dumps(payload))
        return

    start = time.time()
    suite_rows = []
    for suite_name in args.suites:
        print(f"\n=== MELON {suite_name} ===")
        suite_rows.append(_run_worker_subprocess(args, suite_name))

    utility_ok = sum(row["counts"]["benign_success"] for row in suite_rows)
    utility_total = sum(row["counts"]["benign_total"] for row in suite_rows)
    ua_ok = sum(row["counts"]["attacked_utility_success"] for row in suite_rows)
    ua_total = sum(row["counts"]["attacked_total"] for row in suite_rows)
    asr_ok = sum(row["counts"]["attacked_asr_success"] for row in suite_rows)
    asr_total = sum(row["counts"]["attacked_total"] for row in suite_rows)

    result = {
        "schema_version": "melon_agentdojo_v1",
        "model": args.model,
        "attack": args.attack,
        "threshold": args.threshold,
        "elapsed_sec": round(time.time() - start, 1),
        "Utility": round(utility_ok / utility_total * 100, 2) if utility_total else 0.0,
        "Utility_under_attack": round(ua_ok / ua_total * 100, 2) if ua_total else 0.0,
        "Targeted_ASR": round(asr_ok / asr_total * 100, 2) if asr_total else 0.0,
        "UAR_no_atk": round(utility_ok / utility_total * 100, 2) if utility_total else 0.0,
        "UA": round(ua_ok / ua_total * 100, 2) if ua_total else 0.0,
        "ASR": round(asr_ok / asr_total * 100, 2) if asr_total else 0.0,
        "TPR": None,
        "FPR": None,
        "counts": {
            "benign_total": utility_total,
            "benign_success": utility_ok,
            "attacked_total": ua_total,
            "attacked_utility_success": ua_ok,
            "attacked_asr_success": asr_ok,
        },
        "suites": {row["suite"]: row for row in suite_rows},
    }

    out = ROOT / "data" / f"melon_agentdojo_{args.model}_{args.attack}.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    main()
