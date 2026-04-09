"""Run Pysa taint analysis on ALL AgentDojo tool functions.

Pipeline for each tool:
  1. Extract function source from AgentDojo tool file
  2. Rewrite: strip Pydantic annotations, replace C-extension mutations with wrapper methods
  3. Prepend domain types (Python classes with wrapper methods)
  4. Generate Pysa source models (mark user-input params as TaintSource[ToolInput])
  5. Run Pysa with domain sink models
  6. Collect capability findings

No keyword fallback. No hand-labeling. All capabilities derived from taint analysis.
"""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

AGENTDOJO_TOOLS = Path(__file__).resolve().parent.parent.parent / "agentdojo" / "src" / "agentdojo" / "default_suites" / "v1" / "tools"
PYSA_CONFIG = Path(__file__).resolve().parent / "pysa_agentdojo"

CODE_TO_CAP = {
    9001: "code_execution", 9002: "credential_access", 9003: "identity_admin",
    9004: "cross_boundary_egress", 9005: "value_transfer", 9006: "data_destruction",
    9007: "read_identity", 9008: "write_mutate", 9009: "read_private",
    9010: "external_ingestion", 9011: "read_public",
}

# Environment-injected parameter types (Depends-injected, not user input)
ENV_TYPES = {
    "BankAccount", "Inbox", "Calendar", "CloudDrive", "Slack", "Web",
    "AnnotatedSlack", "AnnotatedWeb", "User", "Hotels", "Restaurants",
    "CarRental", "Flights", "Reservation", "Filesystem", "UserAccount",
}


def extract_functions(source_file: Path) -> list[tuple[str, str, list[str]]]:
    """Extract (name, full_source_text, user_params) from a tool source file."""
    full_source = source_file.read_text()
    try:
        tree = ast.parse(full_source)
    except SyntaxError:
        return []

    results = []
    source_lines = full_source.split("\n")

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name.startswith("_"):
            continue
        # Skip class methods (they're internal domain methods, not tool functions)
        # Tool functions are module-level, not inside classes
        for parent in ast.walk(tree):
            if isinstance(parent, ast.ClassDef):
                for child in parent.body:
                    if child is node:
                        break
                else:
                    continue
                break  # This node is inside a class — skip it
        else:
            pass  # Module-level function — process it

        # Get user-input params (skip env-injected params)
        user_params = []
        for arg in node.args.args:
            name = arg.arg
            if name == "self":
                continue
            ann = arg.annotation
            if ann:
                if isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name) and ann.value.id == "Annotated":
                    continue
                if isinstance(ann, ast.Name) and ann.id in ENV_TYPES:
                    continue
            user_params.append(name)

        # Extract source text
        start = node.lineno - 1
        end = node.end_lineno or start + 1
        func_lines = source_lines[start:end]
        func_text = "\n".join(func_lines)

        results.append((node.name, func_text, user_params))

    return results


def rewrite_for_pysa(func_source: str) -> str:
    """Rewrite tool source: strip annotations, replace C-extension patterns with wrappers."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("rewriter", PYSA_CONFIG / "rewriter.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.rewrite_function_for_pysa(func_source)


def run_pysa(func_name: str, func_source: str, user_params: list[str]) -> set[str]:
    """Run Pysa on a single rewritten tool function."""
    if not shutil.which("pyre"):
        return set()

    # Read domain types
    domain_types = (PYSA_CONFIG / "domain_types.py").read_text()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)

        # Combine domain types + rewritten tool function
        full_source = domain_types + "\n\n" + func_source
        (tmppath / "tool_under_analysis.py").write_text(full_source)

        # Copy taint config + sink models
        (tmppath / "taint.config").write_text((PYSA_CONFIG / "taint.config").read_text())
        (tmppath / "agentdojo_sinks.pysa").write_text((PYSA_CONFIG / "agentdojo_sinks.pysa").read_text())

        # Generate source model
        taint_params = [f"{p}: TaintSource[ToolInput]" for p in user_params]
        source_line = f"def tool_under_analysis.{func_name}({', '.join(taint_params)}): ..."
        (tmppath / "tool_sources.pysa").write_text(source_line)

        # Pyre config
        (tmppath / ".pyre_configuration").write_text(
            json.dumps({"source_directories": ["."], "taint_models_path": ["."], "search_path": []})
        )

        results_dir = tmppath / "results"
        result = subprocess.run(
            ["pyre", "analyze", "--no-verify", "--save-results-to", str(results_dir)],
            cwd=str(tmppath), capture_output=True, text=True, timeout=120,
        )

        if result.returncode != 0:
            return set()

        errors_file = results_dir / "errors.json"
        if not errors_file.exists():
            return set()

        try:
            findings = json.loads(errors_file.read_text())
        except json.JSONDecodeError:
            return set()

        caps = set()
        for finding in findings:
            cap = CODE_TO_CAP.get(finding.get("code", 0))
            if cap:
                caps.add(cap)
        return caps


def is_module_level_function(source_file: Path, func_name: str) -> bool:
    """Check if function is defined at module level (not inside a class)."""
    tree = ast.parse(source_file.read_text())
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            return True
    return False


def main():
    tool_files = sorted(AGENTDOJO_TOOLS.glob("*.py"))
    tool_files = [f for f in tool_files if f.name not in ("__init__.py", "types.py")]

    all_results: dict[str, list[str]] = {}
    total = 0
    detected = 0
    t0 = time.time()

    for source_file in tool_files:
        module_name = source_file.stem
        functions = extract_functions(source_file)

        print(f"\n=== {module_name} ===")

        for func_name, func_source, user_params in functions:
            # Only analyze module-level functions (tool endpoints)
            if not is_module_level_function(source_file, func_name):
                continue

            total += 1

            if not user_params:
                print(f"  {func_name:40s} → (no user input params)")
                all_results[func_name] = []
                continue

            rewritten = rewrite_for_pysa(func_source)
            caps = run_pysa(func_name, rewritten, user_params)

            if caps:
                detected += 1

            cap_str = ", ".join(sorted(caps)) if caps else "(none)"
            print(f"  {func_name:40s} → {cap_str}")
            all_results[func_name] = sorted(caps)

    elapsed = time.time() - t0
    print("\n" + "=" * 80)
    print(f"PYSA ANALYSIS: {detected}/{total} tools with capabilities detected ({elapsed:.1f}s)")
    print("=" * 80)

    output_path = Path(__file__).parent / "pysa_agentdojo_results.json"
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"Saved to {output_path}")


if __name__ == "__main__":
    main()
