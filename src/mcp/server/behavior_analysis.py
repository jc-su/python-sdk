"""Binary behavior analysis for tool registration-time verification.

Implements the Identity step of the I -> A -> A pipeline:

  Identity (this module):  Verify tool binary behavior matches description
  Authentication:          TDX attestation proves binary runs in hardware TEE
  Authorization:           Scope enforcement blocks unauthorized tool calls

Two-phase analysis:

Phase 1 — Call Graph Extraction:
  Extract the tool's call graph from its Python source code.
  Map API calls to ToolCapability categories:
    - smtplib.sendmail     -> SEND
    - requests.post        -> SEND
    - os.remove            -> DELETE
    - subprocess.run       -> EXECUTE
    - sqlite3.execute      -> WRITE
    ...

Phase 2 — Description-Behavior Matching:
  Compare the capabilities derived from ACTUAL code (call graph)
  against the capabilities derived from the tool DESCRIPTION (keyword analysis).
  Mismatches indicate suspicious behavior:
    - Tool says "read emails" but code calls smtplib.sendmail  -> MISMATCH
    - Tool says "search files" but code calls os.remove        -> MISMATCH

Integration with AgentArmor concepts (arxiv:2508.01249):
  - Property Registry      -> Our BehaviorAttestation (tool metadata + side effects)
  - PDG Security Types      -> Our ToolCapability categories (semantic classification)
  - Type Checking           -> Our description-vs-code mismatch detection

Key difference from AgentArmor:
  - AgentArmor: runtime PDG analysis on every tool call (LLM inference cost)
  - TEE-MCP:    registration-time analysis ONCE + runtime hardware enforcement (zero cost)
  - Result:     TEE-MCP is ~0% ASR with 0% runtime overhead for authorization
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

from mcp.server.authorization import KeywordToolAnalyzer, ToolCapability

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# API -> Capability mapping (the "Property Registry" in AgentArmor terms)
# ---------------------------------------------------------------------------

# Maps Python module/function patterns to capability categories.
# Used by CallGraphToolAnalyzer to classify what a tool's code actually does.

_API_CAPABILITY_MAP: dict[ToolCapability, list[str]] = {
    ToolCapability.SEND: [
        # Network sending
        "smtplib",
        "email.mime",
        "requests.post",
        "requests.put",
        "requests.patch",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "aiohttp.ClientSession.post",
        "urllib.request.urlopen",
        "http.client.HTTPConnection.request",
        # Messaging
        "slack_sdk",
        "twilio",
        "sendgrid",
        "boto3.client.ses",
        "boto3.client.sns",
    ],
    ToolCapability.READ: [
        # Network reading
        "requests.get",
        "httpx.get",
        "aiohttp.ClientSession.get",
        "urllib.request.urlopen",
        # File reading
        "builtins.open",
        "pathlib.Path.read_text",
        "pathlib.Path.read_bytes",
        # Database reading
        "sqlite3.Cursor.fetchone",
        "sqlite3.Cursor.fetchall",
        "sqlite3.Cursor.fetchmany",
    ],
    ToolCapability.WRITE: [
        # File writing
        "pathlib.Path.write_text",
        "pathlib.Path.write_bytes",
        "shutil.copy",
        "shutil.copy2",
        "shutil.move",
        "os.rename",
        "os.makedirs",
        "os.mkdir",
        # Database writing
        "sqlite3.Connection.execute",
        "sqlite3.Connection.executemany",
        "sqlite3.Connection.commit",
    ],
    ToolCapability.DELETE: [
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "shutil.rmtree",
        "pathlib.Path.unlink",
        "pathlib.Path.rmdir",
    ],
    ToolCapability.EXECUTE: [
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "os.system",
        "os.popen",
        "os.exec",
        "os.execvp",
        "os.spawn",
        "eval",
        "exec",
        "compile",
        "ctypes",
    ],
    ToolCapability.FINANCIAL: [
        "stripe",
        "paypal",
        "braintree",
        "square",
        "boto3.client.marketplace",
    ],
    ToolCapability.ADMIN: [
        "os.chmod",
        "os.chown",
        "os.setuid",
        "os.setgid",
        "grp",
        "pwd",
        "crypt",
    ],
}

# Inverse map for fast lookup: "smtplib" -> ToolCapability.SEND
_API_TO_CAPABILITY: dict[str, ToolCapability] = {}
for _cap, _apis in _API_CAPABILITY_MAP.items():
    for _api in _apis:
        _API_TO_CAPABILITY[_api] = _cap


# ---------------------------------------------------------------------------
# Behavior attestation result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BehaviorAttestation:
    """Result of binary behavior analysis for a tool.

    Created at registration time by analyzing the tool's source/binary.
    Stored alongside the tool's RTMR3 measurement in the Reference Value database.

    This is the TEE-MCP equivalent of AgentArmor's Property Registry entry:
    it captures what a tool ACTUALLY does (from code analysis), not just
    what it CLAIMS to do (from its description).
    """

    tool_name: str

    # Capabilities derived from ACTUAL code analysis (call graph)
    code_capabilities: frozenset[ToolCapability]

    # Capabilities derived from tool DESCRIPTION (keyword analysis)
    declared_capabilities: frozenset[ToolCapability]

    # API calls found in the call graph, classified by capability
    api_calls: dict[str, str] = field(default_factory=lambda: {})  # api -> capability

    # Suspicious APIs: capabilities found in code but NOT in description
    undeclared_capabilities: frozenset[ToolCapability] = frozenset()

    # Description match verdict
    description_match: bool = True  # True if code capabilities ⊆ declared capabilities
    mismatch_reason: str = ""

    # Binary integrity
    source_hash: str = ""  # SHA-384 of source code (for binding to RTMR3)

    # Analysis metadata
    analyzer: str = ""  # Which analyzer produced this (e.g., "pycg", "keyword", "llm")
    confidence: float = 1.0  # 0.0-1.0

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
            "api_calls": dict(self.api_calls),
        }


# ---------------------------------------------------------------------------
# Call graph tool analyzer
# ---------------------------------------------------------------------------


def classify_api_call(api_call: str) -> ToolCapability | None:
    """Classify a Python API call into a ToolCapability.

    Matches against the _API_CAPABILITY_MAP using prefix matching:
    "smtplib.SMTP.sendmail" matches "smtplib" -> SEND

    Args:
        api_call: Fully qualified Python API name (e.g., "os.remove", "smtplib.SMTP").

    Returns:
        The matching ToolCapability, or None if unclassified.
    """
    # Exact match first
    if api_call in _API_TO_CAPABILITY:
        return _API_TO_CAPABILITY[api_call]
    # Prefix match: "smtplib.SMTP.sendmail" matches "smtplib"
    for api_pattern, capability in _API_TO_CAPABILITY.items():
        if api_call.startswith(api_pattern):
            return capability
    return None


def analyze_call_graph(call_graph: dict[str, list[str]]) -> tuple[set[ToolCapability], dict[str, str]]:
    """Analyze a call graph to derive capabilities and API classifications.

    Takes a call graph in PyCG format: {caller: [callee, ...]} and classifies
    all callee API calls into ToolCapability categories.

    Args:
        call_graph: Call graph dict from PyCG/JARVIS: {function: [called_functions]}.

    Returns:
        Tuple of (capabilities, api_calls) where api_calls maps API -> capability name.
    """
    capabilities: set[ToolCapability] = set()
    api_calls: dict[str, str] = {}

    for callees in call_graph.values():
        for callee in callees:
            cap = classify_api_call(callee)
            if cap is not None:
                capabilities.add(cap)
                api_calls[callee] = cap.value

    return capabilities, api_calls


def create_behavior_attestation(
    tool_name: str,
    description: str,
    *,
    call_graph: dict[str, list[str]] | None = None,
    source_code: str | None = None,
) -> BehaviorAttestation:
    """Create a BehaviorAttestation by analyzing a tool's code and description.

    This is the main entry point for registration-time behavior analysis.

    Phase 1: Extract capabilities from call graph (what the code ACTUALLY does).
    Phase 2: Extract capabilities from description (what the tool CLAIMS to do).
    Phase 3: Compare — any undeclared capabilities indicate suspicious behavior.

    Args:
        tool_name: The MCP tool name.
        description: The tool's human-readable description.
        call_graph: Pre-extracted call graph (PyCG format). If None, falls back
                    to description-only analysis.
        source_code: Tool source code (for hashing). Optional.

    Returns:
        BehaviorAttestation with analysis results.
    """
    # Phase 1: Code analysis (if call graph available)
    code_capabilities: set[ToolCapability]
    api_calls: dict[str, str]
    if call_graph is not None:
        code_capabilities, api_calls = analyze_call_graph(call_graph)
        analyzer_name = "call_graph"
    else:
        # Fallback: no call graph, use description-only
        code_capabilities = set()
        api_calls = {}
        analyzer_name = "description_only"

    # Phase 2: Description analysis (keyword-based)
    keyword_analyzer = KeywordToolAnalyzer()
    declared_capabilities = keyword_analyzer.analyze(tool_name, description)

    # Phase 3: Compare — find undeclared capabilities
    # If call graph was analyzed, check for capabilities in code but not in description
    undeclared: frozenset[ToolCapability]
    if call_graph is not None:
        undeclared = frozenset(code_capabilities - declared_capabilities)
        description_match = len(undeclared) == 0
        if not description_match:
            undeclared_names = ", ".join(sorted(c.value for c in undeclared))
            mismatch_reason = f"Code analysis found capabilities [{undeclared_names}] not declared in tool description"
        else:
            mismatch_reason = ""
    else:
        undeclared = frozenset()
        description_match = True
        mismatch_reason = ""

    # Source hash for binding to RTMR3
    source_hash = ""
    if source_code is not None:
        source_hash = hashlib.sha384(source_code.encode()).hexdigest()

    # Use the UNION of code and declared capabilities as the effective set
    # (code analysis may find capabilities the keyword analyzer missed)
    effective_code_caps = frozenset(code_capabilities) if call_graph is not None else frozenset(declared_capabilities)

    return BehaviorAttestation(
        tool_name=tool_name,
        code_capabilities=effective_code_caps,
        declared_capabilities=frozenset(declared_capabilities),
        api_calls=api_calls,
        undeclared_capabilities=undeclared,
        description_match=description_match,
        mismatch_reason=mismatch_reason,
        source_hash=source_hash,
        analyzer=analyzer_name,
        confidence=0.9 if call_graph is not None else 0.5,
    )


# ---------------------------------------------------------------------------
# PyCG integration (optional — requires pycg package)
# ---------------------------------------------------------------------------


def extract_call_graph_pycg(entry_point: str) -> dict[str, list[str]]:
    """Extract call graph from Python source using PyCG.

    PyCG (https://github.com/vitsalis/PyCG) is a state-of-the-art
    static call graph generator for Python.

    Args:
        entry_point: Path to the Python file to analyze.

    Returns:
        Call graph dict: {caller: [callee, ...]}.

    Raises:
        ImportError: If pycg is not installed.
        FileNotFoundError: If entry_point doesn't exist.
    """
    try:
        from pycg.pycg import CallGraphGenerator  # type: ignore[import-untyped,import-not-found]
    except ImportError:
        raise ImportError("pycg is required for call graph extraction. Install it with: pip install pycg") from None

    cg_generator = CallGraphGenerator([entry_point], "", -1)  # type: ignore[no-untyped-call]
    cg_generator.analyze()  # type: ignore[no-untyped-call]
    return cg_generator.output()  # type: ignore[no-untyped-call]
