"""Offline tool behavior analysis for registration-time capability profiling.

Uses Meta's Pysa taint analysis engine to perform interprocedural data-flow
tracking from tool entry points to security-sensitive sinks. Pysa only flags
sinks where tool INPUT actually flows — not just sinks that are syntactically
present. This eliminates false positives that AST-based approaches cannot avoid.

Pipeline:
  1. Parse tool source to extract function signatures (via Python ast)
  2. Generate Pysa source models (mark tool params as TaintSource[ToolInput])
  3. Run Pysa with our taint.config (11 custom sink categories) + .pysa models
  4. Parse Pysa's JSON output → set of ToolCapability values
  5. Compare code-derived capabilities against tool description
  6. Output a CapabilityProfile bound to the tool's source hash

The capability profile is consumed by AuthorizationManager at runtime,
where it is a simple table lookup — no static analysis at runtime.

Requires: pyre-check (`pip install pyre-check`)

References:
  - Pysa: https://pyre-check.org/docs/pysa-basics/
  - Pysa sink models derived from pyre-check/stubs/taint/ (Meta)
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp.server.authorization import KeywordToolAnalyzer, ToolCapability

# Bundled Pysa models directory (ships with the package)
_BUNDLED_PYSA_MODELS = Path(__file__).parent / "pysa_models"

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pysa taint analysis
# ---------------------------------------------------------------------------

# Map Pysa rule codes (from taint.config) to our ToolCapability enum.
# These codes are defined in the taint.config "rules" section.
_CODE_TO_CAPABILITY: dict[int, ToolCapability] = {
    9001: ToolCapability.CODE_EXECUTION,
    9002: ToolCapability.CREDENTIAL_ACCESS,
    9003: ToolCapability.IDENTITY_ADMIN,
    9004: ToolCapability.CROSS_BOUNDARY_EGRESS,
    9005: ToolCapability.VALUE_TRANSFER,
    9006: ToolCapability.DATA_DESTRUCTION,
    9007: ToolCapability.READ_IDENTITY,
    9008: ToolCapability.WRITE_MUTATE,
    9009: ToolCapability.READ_PRIVATE,
    9010: ToolCapability.EXTERNAL_INGESTION,
    9011: ToolCapability.READ_PUBLIC,
}


def analyze_with_pysa(
    source_code: str,
    *,
    taint_config_dir: str | None = None,
    entrypoint: str | None = None,
    timeout: int = 120,
) -> tuple[frozenset[ToolCapability], list[dict[str, Any]]]:
    """Run Pysa taint analysis on tool source code.

    Performs interprocedural fixed-point taint propagation from tool entry
    points to security-sensitive sinks. Only flags sinks where tool INPUT
    actually flows — hardcoded paths or constants are NOT flagged.

    Args:
        source_code: Python source code to analyze.
        taint_config_dir: Directory containing taint.config and .pysa model files.
                          Defaults to bundled models in pysa_models/.
        entrypoint: Optional function name to scope analysis to.
        timeout: Max seconds for Pysa to run.

    Returns:
        Tuple of (capabilities, raw_findings) where raw_findings are the
        Pysa JSON error objects for detailed inspection.
    """
    import ast
    import json
    import shutil
    import subprocess
    import tempfile

    if not shutil.which("pyre"):
        logger.warning("Pysa not available: pyre not found in PATH")
        return frozenset(), []

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)

        # Write source file
        (tmppath / "tool_under_analysis.py").write_text(source_code)

        # Copy taint config and sink models (bundled or custom)
        config_dir = Path(taint_config_dir) if taint_config_dir else _BUNDLED_PYSA_MODELS
        for f in config_dir.glob("*.pysa"):
            (tmppath / f.name).write_text(f.read_text())
        taint_config = config_dir / "taint.config"
        if taint_config.exists():
            (tmppath / "taint.config").write_text(taint_config.read_text())

        # Copy bundled type stubs for third-party libraries (requests, httpx, etc.)
        # and typeshed overrides (shutil.rmtree Protocol → plain def)
        search_paths: list[str] = []
        stubs_dir = config_dir / "stubs"
        if stubs_dir.is_dir():
            dest_stubs = tmppath / "stubs"
            shutil.copytree(str(stubs_dir), str(dest_stubs))
            search_paths.append("stubs")
        overrides_dir = config_dir / "typeshed_overrides"
        if overrides_dir.is_dir():
            dest_overrides = tmppath / "typeshed_overrides"
            shutil.copytree(str(overrides_dir), str(dest_overrides))
            search_paths.append("typeshed_overrides")

        # Generate source models from actual function signatures
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            logger.warning("Failed to parse source code")
            return frozenset(), []

        source_lines = _generate_source_models(tree, entrypoint)
        if not source_lines:
            return frozenset(), []
        (tmppath / "tool_sources.pysa").write_text("\n".join(source_lines))

        # Pyre configuration
        (tmppath / ".pyre_configuration").write_text(
            json.dumps({"source_directories": ["."], "taint_models_path": ["."], "search_path": search_paths})
        )

        # Run Pysa
        results_dir = tmppath / "results"
        result = subprocess.run(
            ["pyre", "analyze", "--no-verify", "--save-results-to", str(results_dir)],
            cwd=str(tmppath),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            logger.warning("Pysa analysis failed: %s", result.stderr[:500])
            return frozenset(), []

        # Parse results
        errors_file = results_dir / "errors.json"
        if not errors_file.exists():
            return frozenset(), []

        try:
            findings = json.loads(errors_file.read_text())
        except json.JSONDecodeError:
            return frozenset(), []

        # Convert findings to capabilities
        capabilities: set[ToolCapability] = set()
        for finding in findings:
            cap = _CODE_TO_CAPABILITY.get(finding.get("code", 0))
            if cap is not None:
                capabilities.add(cap)

        return frozenset(capabilities), findings


def _generate_source_models(tree: Any, entrypoint: str | None = None) -> list[str]:
    """Generate .pysa source model lines marking tool params as tainted.

    Pysa requires models to match ACTUAL parameter names from the source.
    This function extracts real parameter names from the AST and annotates
    each with TaintSource[ToolInput].
    """
    import ast

    taint = "TaintSource[ToolInput]"
    module = "tool_under_analysis"
    lines: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if entrypoint and node.name != entrypoint:
            continue
        if node.name.startswith("_"):
            continue

        params: list[str] = []
        for arg in node.args.args:
            if arg.arg == "self":
                params.append("self")
            else:
                params.append(f"{arg.arg}: {taint}")

        lines.append(f"def {module}.{node.name}({', '.join(params)}): ...")

    return lines


# ---------------------------------------------------------------------------
# Capability profile (output of offline analysis)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityProfile:
    """Result of offline behavior analysis for a tool.

    Created at registration time. Bound to the tool's source hash,
    which in turn is bound to the container's RTMR3 measurement.
    Consumed by AuthorizationManager at runtime as a simple lookup.
    """

    tool_name: str
    code_capabilities: frozenset[ToolCapability]
    declared_capabilities: frozenset[ToolCapability]
    findings: list[dict[str, Any]] = field(default_factory=lambda: [])
    undeclared_capabilities: frozenset[ToolCapability] = frozenset()
    description_match: bool = True
    mismatch_reason: str = ""
    source_hash: str = ""
    analyzer: str = "pysa"
    confidence: float = 0.95

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "code_capabilities": sorted(c.value for c in self.code_capabilities),
            "declared_capabilities": sorted(c.value for c in self.declared_capabilities),
            "undeclared_capabilities": sorted(c.value for c in self.undeclared_capabilities),
            "description_match": self.description_match,
            "mismatch_reason": self.mismatch_reason,
            "source_hash": self.source_hash,
            "analyzer": self.analyzer,
            "confidence": self.confidence,
            "findings_count": len(self.findings),
        }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def build_capability_profile(
    tool_name: str,
    description: str,
    *,
    source_code: str | None = None,
    taint_config_dir: str | None = None,
    entrypoint: str | None = None,
) -> CapabilityProfile:
    """Build a CapabilityProfile for a tool using Pysa taint analysis.

    Offline analysis pipeline:
      1. Run Pysa on source code → taint-flow-derived capabilities
      2. Run KeywordToolAnalyzer on description → declared capabilities
      3. Compare: capabilities in code but not in description = suspicious

    Args:
        tool_name: The MCP tool name.
        description: The tool's human-readable description.
        source_code: Tool source code. If None, falls back to description-only.
        taint_config_dir: Directory with taint.config and .pysa models.
        entrypoint: Function name to scope analysis to.

    Returns:
        CapabilityProfile with analysis results.
    """
    # Phase 1: Code analysis via Pysa
    code_capabilities: frozenset[ToolCapability]
    findings: list[dict[str, Any]]
    analyzer_name: str

    if source_code is not None:
        code_capabilities, findings = analyze_with_pysa(
            source_code,
            taint_config_dir=taint_config_dir,
            entrypoint=entrypoint,
        )
        analyzer_name = "pysa"
    else:
        code_capabilities = frozenset()
        findings = []
        analyzer_name = "description_only"

    # Phase 2: Description analysis (keyword-based)
    declared_capabilities = frozenset(KeywordToolAnalyzer().analyze(tool_name, description))

    # Phase 3: Mismatch detection
    undeclared: frozenset[ToolCapability]
    if code_capabilities:
        undeclared = code_capabilities - declared_capabilities
        description_match = len(undeclared) == 0
        mismatch_reason = ""
        if not description_match:
            names = ", ".join(sorted(c.value for c in undeclared))
            mismatch_reason = f"Pysa found undeclared capabilities: [{names}]"
    else:
        undeclared = frozenset()
        description_match = True
        mismatch_reason = ""

    source_hash = hashlib.sha384(source_code.encode()).hexdigest() if source_code else ""
    effective = code_capabilities if code_capabilities else declared_capabilities

    return CapabilityProfile(
        tool_name=tool_name,
        code_capabilities=effective,
        declared_capabilities=declared_capabilities,
        findings=findings,
        undeclared_capabilities=undeclared,
        description_match=description_match,
        mismatch_reason=mismatch_reason,
        source_hash=source_hash,
        analyzer=analyzer_name,
        confidence=0.95 if code_capabilities else 0.5,
    )
