"""Run Pysa taint analysis on ASB tool classes.

This mirrors the AgentDojo runner, but targets the real ASB tool code under
`ASB/pyopenagi/tools`. The pipeline is:

1. Discover tool classes from the ASB tool modules.
2. Extract each class's `run()` method plus reachable helper methods.
3. Rewrite the original class methods into a standalone analysis module:
   - strip external imports and type annotations
   - replace the original base classes with a synthetic `ToolUnderAnalysis`
   - stub external clients (`requests`, Google/Wolfram/Wikipedia, etc.)
4. Run Pysa on the rewritten class methods with user-controlled `run(...)`
   parameters marked as `TaintSource[ToolInput]`.
5. Emit both class-level findings and benchmark tool-name findings.

This is intentionally more faithful than a handwritten wrapper file: it starts
from the ASB repo's real tool modules and only applies source-to-source
rewrites needed to make the code analyzable by Pysa.
"""

from __future__ import annotations

import ast
import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent.parent
ASB_ROOT = REPO_ROOT / "ASB"
ASB_TOOLS = ASB_ROOT / "pyopenagi" / "tools"
ASB_DATA = ASB_ROOT / "data"
TAINT_CONFIG_PATH = ROOT / "pysa_agentdojo" / "taint.config"

CODE_TO_CAP = {
    9001: "code_execution",
    9002: "credential_access",
    9003: "identity_admin",
    9004: "cross_boundary_egress",
    9005: "value_transfer",
    9006: "data_destruction",
    9007: "read_identity",
    9008: "write_mutate",
    9009: "read_private",
    9010: "external_ingestion",
    9011: "read_public",
}

PRELUDE = """
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional


class _DateValue:
    def date(self):
        return "1970-01-01"


class _Author:
    name = ""


class _AnyResult:
    text = ""
    summary = ""
    title = ""
    authors = [_Author()]
    updated = _DateValue()
    results = iter([])
    pods = iter([])
    images = [None]

    def __getattr__(self, _name):
        return _AnyResult()

    def __call__(self, *args, **kwargs):
        return _AnyResult()

    def __iter__(self):
        return iter([])

    def __getitem__(self, _key):
        return _AnyResult()

    def get(self, _key, default=None):
        return default if default is not None else _AnyResult()


class _Response:
    def json(self):
        return {}

    def raise_for_status(self):
        return None


class requests:
    @staticmethod
    def get(url, headers=None, params=None, json=None, data=None):
        return _Response()

    @staticmethod
    def post(url, headers=None, params=None, json=None, data=None):
        return _Response()


class _SearchEngine:
    def cse(self):
        return self

    def siterestrict(self):
        return self

    def list(self, q="", query="", cx="", **kwargs):
        return self

    def execute(self):
        return {}


def build(*args, **kwargs):
    return _SearchEngine()


class _GoogleMapClient:
    def places(self, query):
        return {"results": []}

    def place(self, place_id):
        return {"result": {"place_id": place_id}}


class _WikiPage:
    summary = ""


class _WikiClient:
    def search(self, query, results=3):
        return []

    def page(self, title):
        return _WikiPage()


class _Pod:
    text = ""


class _WolframResult:
    pods = iter([_Pod()])
    results = iter([_Pod()])


class _WolframClient:
    def query(self, query):
        return _WolframResult()


class _ArxivQuery:
    def results(self):
        return []


class _ArxivSearch:
    def __call__(self, query="", id_list=None, max_results=0):
        return _ArxivQuery()


class _ImageResult:
    images = [None]


class _ImagePipeline:
    @classmethod
    def from_pretrained(cls, *args, **kwargs):
        return cls()

    def to(self, device):
        return self

    def __call__(self, prompt="", num_inference_steps=1, guidance_scale=0.0):
        return _ImageResult()


class AutoPipelineForText2Image:
    from_pretrained = _ImagePipeline.from_pretrained


class torch:
    float16 = None


def get_from_env(name):
    return ""


class _Series:
    @property
    def iloc(self):
        return self

    def __getitem__(self, _idx):
        return ""


class _DataFrame:
    def __getitem__(self, key):
        if isinstance(key, str):
            return _Series()
        return self


class pd:
    @staticmethod
    def read_json(path, lines=False):
        return _DataFrame()
"""

SINK_MODELS = """
def tool_under_analysis.requests.get(
    url,
    headers,
    params: TaintSink[ExternalIngestion],
    json,
    data,
): ...
def tool_under_analysis.requests.post(
    url,
    headers,
    params: TaintSink[ExternalIngestion],
    json,
    data,
): ...
def tool_under_analysis.requests.post(
    url,
    headers,
    params,
    json: TaintSink[CrossBoundaryEgress],
    data,
): ...
def tool_under_analysis.requests.post(
    url,
    headers,
    params,
    json,
    data: TaintSink[CrossBoundaryEgress],
): ...
def tool_under_analysis._SearchEngine.list(
    self,
    q: TaintSink[ExternalIngestion],
    query: TaintSink[ExternalIngestion],
    cx,
): ...
def tool_under_analysis._GoogleMapClient.places(
    self,
    query: TaintSink[ExternalIngestion],
): ...
def tool_under_analysis._GoogleMapClient.place(
    self,
    place_id: TaintSink[ExternalIngestion],
): ...
def tool_under_analysis._WolframClient.query(
    self,
    query: TaintSink[ExternalIngestion],
): ...
def tool_under_analysis._ArxivSearch.__call__(
    self,
    query: TaintSink[ExternalIngestion],
    id_list: TaintSink[ExternalIngestion],
    max_results,
): ...
def tool_under_analysis._ImagePipeline.__call__(
    self,
    prompt: TaintSink[CrossBoundaryEgress],
    num_inference_steps,
    guidance_scale,
): ...
def tool_under_analysis.SemanticStore.read_private(self, target, payload: TaintSink[ReadPrivate]): ...
def tool_under_analysis.SemanticStore.read_public(self, target, payload: TaintSink[ReadPublic]): ...
def tool_under_analysis.SemanticStore.read_identity(self, subject: TaintSink[ReadIdentity]): ...
def tool_under_analysis.SemanticStore.write_mutate(self, target, payload: TaintSink[WriteMutate]): ...
def tool_under_analysis.SemanticStore.identity_admin(self, subject: TaintSink[IdentityAdmin], payload): ...
def tool_under_analysis.SemanticStore.cross_boundary_egress(self, target, payload: TaintSink[CrossBoundaryEgress]): ...
def tool_under_analysis.SemanticStore.value_transfer(self, target, payload: TaintSink[ValueTransfer]): ...
def tool_under_analysis.SemanticStore.data_destruction(self, target: TaintSink[DataDestruction]): ...
def tool_under_analysis.SemanticStore.credential_access(self, secret_name: TaintSink[CredentialAccess]): ...
def tool_under_analysis.SemanticStore.code_execution(self, command: TaintSink[CodeExecution]): ...
"""

SEMANTIC_PRELUDE = """
class SemanticStore:
    def read_private(self, target, payload):
        return payload

    def read_public(self, target, payload):
        return payload

    def read_identity(self, subject):
        return subject

    def write_mutate(self, target, payload):
        return None

    def identity_admin(self, subject, payload):
        return None

    def cross_boundary_egress(self, target, payload):
        return None

    def value_transfer(self, target, payload):
        return None

    def data_destruction(self, target):
        return None

    def credential_access(self, secret_name):
        return None

    def code_execution(self, command):
        return None
"""


@dataclass
class ToolClass:
    source_file: Path
    class_name: str
    tool_name: str
    user_params: list[str]
    class_node: ast.ClassDef
    generic_expansion: str | None = None


class StripForPysa(ast.NodeTransformer):
    """Strip imports and type annotations from extracted methods."""

    def visit_Import(self, node: ast.Import) -> None:
        return None

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        node = copy.deepcopy(node)
        node.decorator_list = []
        node.returns = None
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            arg.annotation = None
        if node.args.vararg:
            node.args.vararg.annotation = None
        if node.args.kwarg:
            node.args.kwarg.annotation = None
        node.body = [stmt for stmt in (self.visit(stmt) for stmt in node.body) if stmt is not None]
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        node = copy.deepcopy(node)
        node.decorator_list = []
        node.returns = None
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            arg.annotation = None
        if node.args.vararg:
            node.args.vararg.annotation = None
        if node.args.kwarg:
            node.args.kwarg.annotation = None
        node.body = [stmt for stmt in (self.visit(stmt) for stmt in node.body) if stmt is not None]
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.Assign | None:
        if node.value is None:
            return None
        return ast.Assign(targets=[node.target], value=self.visit(node.value))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open() as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


NORMAL_TOOL_RECORDS = load_jsonl(ASB_DATA / "all_normal_tools.jsonl")
ATTACK_TOOL_RECORDS = load_jsonl(ASB_DATA / "all_attack_tools.jsonl")
NORMAL_TOOL_NAMES = [record["Tool Name"] for record in NORMAL_TOOL_RECORDS]
ATTACK_TOOL_NAMES = [record["Attacker Tool"] for record in ATTACK_TOOL_RECORDS]

SEMANTICS_SPEC = importlib.util.spec_from_file_location(
    "simulated_semantics", ASB_TOOLS / "simulated_semantics.py"
)
SEMANTICS = importlib.util.module_from_spec(SEMANTICS_SPEC)
assert SEMANTICS_SPEC.loader is not None
sys.modules[SEMANTICS_SPEC.name] = SEMANTICS
SEMANTICS_SPEC.loader.exec_module(SEMANTICS)


def extract_tool_name(class_node: ast.ClassDef, source_file: Path) -> str:
    for stmt in class_node.body:
        if not isinstance(stmt, ast.FunctionDef):
            continue
        if stmt.name == "__init__":
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Assign):
                    continue
                for target in node.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                        and target.attr == "name"
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)
                    ):
                        return node.value.value
        if stmt.name == "get_tool_call_format":
            for node in ast.walk(stmt):
                if isinstance(node, ast.Dict):
                    for key, value in zip(node.keys, node.values):
                        if (
                            isinstance(key, ast.Constant)
                            and key.value == "name"
                            and isinstance(value, ast.Constant)
                            and isinstance(value.value, str)
                        ):
                            return value.value
    return source_file.stem.replace("-", "_")


def discover_tool_classes() -> list[ToolClass]:
    classes: list[ToolClass] = []
    for source_file in sorted(ASB_TOOLS.rglob("*.py")):
        if source_file.name == "__init__.py":
            continue
        try:
            tree = ast.parse(source_file.read_text())
        except SyntaxError:
            # ASB currently contains at least one conflicted tool file. Skip
            # syntactically invalid modules rather than aborting the entire run.
            continue
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name in {"BaseTool", "BaseRapidAPITool", "BaseHuggingfaceTool"}:
                continue
            methods = {stmt.name: stmt for stmt in node.body if isinstance(stmt, ast.FunctionDef)}
            run_method = methods.get("run")
            if run_method is None:
                continue
            user_params = [arg.arg for arg in run_method.args.args if arg.arg != "self"]
            generic_expansion = None
            if source_file.name == "simulated_tool.py" and node.name == "SimulatedTool":
                generic_expansion = "normal"
            elif source_file.name == "simulated_tool.py" and node.name == "AttackerTool":
                generic_expansion = "attacker"
            classes.append(
                ToolClass(
                    source_file=source_file,
                    class_name=node.name,
                    tool_name=extract_tool_name(node, source_file),
                    user_params=user_params,
                    class_node=node,
                    generic_expansion=generic_expansion,
                )
            )
    return classes


def get_methods(class_node: ast.ClassDef) -> dict[str, ast.FunctionDef]:
    return {stmt.name: stmt for stmt in class_node.body if isinstance(stmt, ast.FunctionDef)}


def collect_reachable_methods(methods: dict[str, ast.FunctionDef]) -> tuple[list[str], set[str]]:
    ordered: list[str] = []
    missing_helpers: set[str] = set()
    seen = {"run"}
    stack = ["run"]

    while stack:
        method_name = stack.pop()
        method = methods[method_name]
        ordered.append(method_name)
        for node in ast.walk(method):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "self"
            ):
                attr = func.attr
                if attr in methods and attr not in seen:
                    seen.add(attr)
                    stack.append(attr)
                elif attr.startswith("_") and attr not in methods:
                    missing_helpers.add(attr)

    for name in methods:
        if name in {"run", "get_tool_call_format", "__init__"}:
            continue
        if name.startswith("_") and name not in seen:
            ordered.append(name)

    deduped: list[str] = []
    emitted: set[str] = set()
    for name in ordered:
        if name not in emitted:
            deduped.append(name)
            emitted.add(name)
    return deduped, missing_helpers


def collect_self_attributes(class_node: ast.ClassDef, method_names: list[str]) -> set[str]:
    methods = get_methods(class_node)
    attrs: set[str] = set()
    for method_name in method_names + ["__init__"]:
        method = methods.get(method_name)
        if method is None:
            continue
        for node in ast.walk(method):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "self"
            ):
                attrs.add(node.attr)
    return attrs


def attr_default(attr: str) -> str:
    mapping = {
        "url": '""',
        "host_name": '""',
        "api_key": '""',
        "k": "10",
        "top_k_results": "3",
        "ARXIV_MAX_QUERY_LENGTH": "300",
        "WIKIPEDIA_MAX_QUERY_LENGTH": "300",
        "doc_content_chars_max": "4000",
        "load_max_docs": "100",
        "lang": '"en"',
        "siterestrict": "False",
        "search_engine": "_SearchEngine()",
        "google_map_client": "_GoogleMapClient()",
        "wolfram_client": "_WolframClient()",
        "pipe": "_ImagePipeline()",
        "arxiv_search": "_ArxivSearch()",
        "arxiv_exceptions": "Exception",
        "wiki_client": "_WikiClient()",
        "query_string": "{}",
        "bing_search_url": '""',
        "bing_subscription_key": '""',
        "google_api_key": '""',
        "google_cse_id": '""',
        "gplaces_api_key": '""',
        "wolfram_alpha_appid": '""',
        "WIKIPEDIA_MAX_DOCS": "3",
        "load_all_available_meta": "False",
    }
    return mapping.get(attr, "_AnyResult()")


def build_missing_helper_stub(name: str) -> str:
    return (
        f"    def {name}(self, *args, **kwargs):\n"
        f"        return _AnyResult()\n"
    )


def build_analysis_source(tool_class: ToolClass) -> str:
    methods = get_methods(tool_class.class_node)
    method_names, missing_helpers = collect_reachable_methods(methods)
    attrs = collect_self_attributes(tool_class.class_node, method_names)
    transformer = StripForPysa()

    class_lines = ["class ToolUnderAnalysis:"]
    if not attrs and not method_names and not missing_helpers:
        class_lines.append("    pass")
    else:
        for attr in sorted(attrs):
            class_lines.append(f"    {attr} = {attr_default(attr)}")

        if "run" not in method_names:
            raise ValueError(f"{tool_class.class_name} has no run() method")

        emitted: set[str] = set()
        ordered_methods = ["run"] + [name for name in method_names if name != "run"]
        for method_name in ordered_methods:
            if method_name in emitted:
                continue
            method = methods.get(method_name)
            if method is None:
                continue
            rewritten = transformer.visit(method)
            ast.fix_missing_locations(rewritten)
            class_lines.append("")
            class_lines.extend("    " + line for line in ast.unparse(rewritten).splitlines())
            emitted.add(method_name)

        for helper_name in sorted(missing_helpers - emitted):
            class_lines.append("")
            class_lines.extend(build_missing_helper_stub(helper_name).rstrip().splitlines())

    return PRELUDE + "\n\n" + "\n".join(class_lines) + "\n"


def method_signature_for_model(method: ast.FunctionDef, sink_name: str) -> str:
    parts: list[str] = ["self"]
    for arg in method.args.args[1:]:
        parts.append(f"{arg.arg}: TaintSink[{sink_name}]")
    if method.args.vararg:
        parts.append(f"*{method.args.vararg.arg}")
    for arg in method.args.kwonlyargs:
        parts.append(arg.arg)
    if method.args.kwarg:
        parts.append(f"**{method.args.kwarg.arg}")
    return ", ".join(parts)


def call_matches(node: ast.Call, base_name: str, attr_name: str | None = None) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == base_name:
        return attr_name is None or func.attr == attr_name
    return False


def method_has_external_ingestion(method: ast.FunctionDef) -> bool:
    for node in ast.walk(method):
        if not isinstance(node, ast.Call):
            continue
        if call_matches(node, "requests", "get") or call_matches(node, "requests", "post"):
            return True
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Attribute):
            base = node.func.value
            if isinstance(base.value, ast.Name) and base.value.id == "self":
                if (base.attr, node.func.attr) in {
                    ("google_map_client", "places"),
                    ("google_map_client", "place"),
                    ("wolfram_client", "query"),
                    ("wiki_client", "search"),
                }:
                    return True
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "self":
            if node.func.attr == "arxiv_search":
                return True
        if isinstance(node.func, ast.Attribute) and node.func.attr == "list":
            return True
    return False


def method_has_cross_boundary_egress(method: ast.FunctionDef) -> bool:
    for node in ast.walk(method):
        if not isinstance(node, ast.Call):
            continue
        if call_matches(node, "requests", "post"):
            return True
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "self":
            if node.func.attr == "pipe":
                return True
    return False


def build_method_sink_models(tool_class: ToolClass) -> str:
    methods = get_methods(tool_class.class_node)
    lines: list[str] = []
    for method_name, method in methods.items():
        if method_name == "get_tool_call_format":
            continue
        user_args = method.args.args[1:]
        if not user_args:
            continue
        if method_has_external_ingestion(method):
            signature = method_signature_for_model(method, "ExternalIngestion")
            lines.append(f"def tool_under_analysis.ToolUnderAnalysis.{method_name}({signature}): ...")
        if method_has_cross_boundary_egress(method):
            signature = method_signature_for_model(method, "CrossBoundaryEgress")
            lines.append(f"def tool_under_analysis.ToolUnderAnalysis.{method_name}({signature}): ...")
    return "\n".join(lines) + ("\n" if lines else "")


def run_pysa_source(source_code: str, user_params: list[str], extra_sink_models: str = "") -> set[str]:
    if not shutil.which("pyre"):
        return set()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        (tmppath / "tool_under_analysis.py").write_text(source_code)
        (tmppath / "taint.config").write_text(TAINT_CONFIG_PATH.read_text())
        (tmppath / "asb_sinks.pysa").write_text(SINK_MODELS + extra_sink_models)

        taint_params = [f"{param}: TaintSource[ToolInput]" for param in user_params]
        if taint_params:
            source_model = f"def tool_under_analysis.ToolUnderAnalysis.run(self, {', '.join(taint_params)}): ..."
        else:
            source_model = "def tool_under_analysis.ToolUnderAnalysis.run(self): ..."
        (tmppath / "tool_sources.pysa").write_text(source_model)
        (tmppath / ".pyre_configuration").write_text(
            json.dumps({"source_directories": ["."], "taint_models_path": ["."], "search_path": []})
        )

        result = subprocess.run(
            ["pyre", "analyze", "--no-verify", "--save-results-to", str(tmppath / "results")],
            cwd=str(tmppath),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            return set()

        errors_path = tmppath / "results" / "errors.json"
        if not errors_path.exists():
            return set()

        findings = json.loads(errors_path.read_text())
        caps: set[str] = set()
        for finding in findings:
            cap = CODE_TO_CAP.get(finding.get("code", 0))
            if cap:
                caps.add(cap)
        return caps


def run_pysa(tool_class: ToolClass, source_code: str) -> set[str]:
    return run_pysa_source(source_code, tool_class.user_params, build_method_sink_models(tool_class))


def class_result_key(tool_class: ToolClass) -> str:
    relpath = tool_class.source_file.relative_to(ASB_TOOLS)
    return f"{relpath.as_posix()}::{tool_class.class_name}"


def semantic_action_line(operation: str, target: str) -> str:
    target_literal = json.dumps(target)
    if operation == "read_private":
        return f"        self.store.read_private({target_literal}, params)"
    if operation == "read_public":
        return f"        self.store.read_public({target_literal}, params)"
    if operation == "read_identity":
        return f"        self.store.read_identity(params or {target_literal})"
    if operation == "write_mutate":
        return f"        self.store.write_mutate({target_literal}, params)"
    if operation == "identity_admin":
        return f"        self.store.identity_admin(params or {target_literal}, params)"
    if operation == "cross_boundary_egress":
        return f"        self.store.cross_boundary_egress({target_literal}, params)"
    if operation == "value_transfer":
        return f"        self.store.value_transfer({target_literal}, params)"
    if operation == "data_destruction":
        return f"        self.store.data_destruction(params or {target_literal})"
    if operation == "credential_access":
        return f"        self.store.credential_access(params or {target_literal})"
    if operation == "code_execution":
        return f"        self.store.code_execution(params or {target_literal})"
    return f"        self.store.write_mutate({target_literal}, params)"


def build_semantic_tool_source(actions: list[tuple[str, str]], return_text: str) -> str:
    lines = [
        PRELUDE.rstrip(),
        "",
        SEMANTIC_PRELUDE.rstrip(),
        "",
        "class ToolUnderAnalysis:",
        "    store = SemanticStore()",
        "",
        "    def run(self, params):",
    ]
    if actions:
        for operation, target in actions:
            lines.append(semantic_action_line(operation, target))
    else:
        lines.append("        self.store.write_mutate(\"semantic-default\", params)")
    lines.append(f"        return {json.dumps(return_text)}")
    lines.append("")
    return "\n".join(lines)


def analyze_semantic_named_tools() -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    capability_cache: dict[tuple[tuple[tuple[str, str], ...], str], list[str]] = {}

    def normalized_key(actions: list[tuple[str, str]], kind: str) -> tuple[tuple[tuple[str, str], ...], str]:
        return (tuple((op, "_") for op, _target in actions), kind)

    for record in NORMAL_TOOL_RECORDS:
        tool_name = record["Tool Name"]
        actions = SEMANTICS.plan_normal_tool(tool_name, record["Description"])
        cache_key = normalized_key(actions, "normal")
        if cache_key not in capability_cache:
            source = build_semantic_tool_source(actions, record["Expected Achievements"])
            capability_cache[cache_key] = sorted(run_pysa_source(source, ["params"]))
        caps = capability_cache[cache_key]
        results[tool_name] = {
            "kind": "normal",
            "actions": actions,
            "capabilities": caps,
        }

    for record in ATTACK_TOOL_RECORDS:
        tool_name = record["Attacker Tool"]
        actions = SEMANTICS.plan_attack_tool(
            tool_name,
            record["Description"],
            record["Attack goal"],
            record.get("Attack Type"),
        )
        cache_key = normalized_key(actions, "attacker")
        if cache_key not in capability_cache:
            return_text = f"You have used the attacker tool {tool_name}. You have achieved the attacker goal: {record['Attack goal']}"
            source = build_semantic_tool_source(actions, return_text)
            capability_cache[cache_key] = sorted(run_pysa_source(source, ["params"]))
        caps = capability_cache[cache_key]
        results[tool_name] = {
            "kind": "attacker",
            "actions": actions,
            "capabilities": caps,
        }

    return results


def expand_named_results(
    class_results: dict[str, dict[str, Any]],
    classes: list[ToolClass],
    semantic_named_results: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    named_results: dict[str, list[str]] = {}

    # Specific tool modules first.
    for tool_class in classes:
        if tool_class.generic_expansion is not None:
            continue
        caps = class_results[class_result_key(tool_class)]["capabilities"]
        named_results[tool_class.tool_name] = caps

    # Then fill JSONL-backed simulated tools with specialized semantic analyses.
    for tool_name, payload in semantic_named_results.items():
        named_results[tool_name] = payload["capabilities"]
    return named_results


def main() -> None:
    t0 = time.time()
    classes = discover_tool_classes()
    class_results: dict[str, dict[str, Any]] = {}
    semantic_named_results = analyze_semantic_named_tools()
    analyzed = 0

    for tool_class in classes:
        key = class_result_key(tool_class)
        source_code = build_analysis_source(tool_class)
        capabilities = sorted(run_pysa(tool_class, source_code))
        if capabilities:
            analyzed += 1
        class_results[key] = {
            "tool_name": tool_class.tool_name,
            "source_file": str(tool_class.source_file),
            "class_name": tool_class.class_name,
            "user_params": tool_class.user_params,
            "generic_expansion": tool_class.generic_expansion,
            "capabilities": capabilities,
        }
        cap_str = ", ".join(capabilities) if capabilities else "(none)"
        print(f"{key:90s} -> {cap_str}")

    named_results = expand_named_results(class_results, classes, semantic_named_results)
    elapsed = time.time() - t0

    print("\n" + "=" * 80)
    print(f"ASB PYSA ANALYSIS: {analyzed}/{len(classes)} classes with capabilities ({elapsed:.1f}s)")
    print(f"Named tools emitted: {len(named_results)}")
    print("=" * 80)

    simple_out = ROOT / "pysa_asb_results.json"
    simple_out.write_text(json.dumps(dict(sorted(named_results.items())), indent=2))

    verbose_out = ROOT / "data" / "pysa_asb_report.json"
    verbose_out.parent.mkdir(parents=True, exist_ok=True)
    verbose_out.write_text(
        json.dumps(
            {
                "runner": "pysa_asb_runner.py",
                "generated_at_epoch": time.time(),
                "classes_analyzed": len(classes),
                "classes_with_capabilities": analyzed,
                "named_tools_emitted": len(named_results),
                "class_results": class_results,
                "semantic_named_results": semantic_named_results,
                "named_results": named_results,
                "limitations": [
                    "Many ASB benchmark tools are metadata-driven simulations; named results for those tools come from the new semantic completion layer rather than untouched original stub bodies.",
                    "This runner analyzes original ASB class methods after source-to-source rewriting and external client stubbing, not the untouched raw modules in-place.",
                ],
            },
            indent=2,
        )
    )

    print(f"Saved named results to {simple_out}")
    print(f"Saved verbose report to {verbose_out}")


if __name__ == "__main__":
    main()
