from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterator
from pathlib import Path
from typing import Any
import ast
import json
import re

from jsonschema import Draft202012Validator

from .models import Edge, Node, NodeType, VariableRef, WorkflowIR, file_sha256, stable_id


MAX_DSL_BYTES = 10 * 1024 * 1024
MAX_NODES = 5000
MAX_DEPTH = 100

NODE_TYPES = {
    "HEAD": NodeType.INPUT,
    "TEMPLATE": NodeType.OUTPUT,
    "INTERMEDIATE_OUTPUT": NodeType.OUTPUT,
    "MODEL": NodeType.LLM,
    "AGENT": NodeType.AGENT,
    "AI_PLUGIN": NodeType.TOOL,
    "API_PLUGIN": NodeType.TOOL,
    "MCP": NodeType.TOOL,
    "WORKFLOW": NodeType.TOOL,
    "NEW_KNOWLEDGE": NodeType.KNOWLEDGE,
    "CODE": NodeType.CODE,
    "JUDGE": NodeType.CONDITION,
    "LOOP": NodeType.LOOP,
    "LOOP_START": NodeType.STRUCTURAL,
    "LOOP_OUTPUT": NodeType.STRUCTURAL,
}

SECRET_RE = re.compile(
    r"(?ix)(?:"
    r"(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|authorization)\s*[:=]\s*(?:bearer\s+)?['\"]?[A-Za-z0-9_\-./+=]{8,}"
    r"|bearer\s+[A-Za-z0-9._~+/=-]{12,}|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b"
    r"|\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}|-----BEGIN(?: RSA| EC| OPENSSH)? PRIVATE KEY-----)"
)
PLACEHOLDER_RE = re.compile(r"(?ix)(?:example|placeholder|dummy|<redacted>|your[_-]?(?:key|token|secret)|\*{3,})")
HIGH_IMPACT_WORDS = {
    "delete", "remove", "drop", "destroy", "purge", "transfer", "payment", "refund",
    "grant", "revoke", "permission", "admin", "publish", "send", "upload",
    "删除", "销毁", "转账", "付款", "退款", "授权", "提权", "发布", "发送",
}
SENSITIVE_WORDS = {
    "password", "secret", "token", "credential", "authorization", "id_card", "phone",
    "email", "account", "customer", "user_id", "userid", "身份证", "手机号", "客户", "账号", "密钥",
}
CONTROL_WORDS = {"validate", "policy", "authorize", "approval", "guard", "审核", "授权", "校验", "审批"}

COMMON_NODE_FIELDS = {"id", "icon", "type", "label", "description", "paramList", "outputName", "outputType"}
NODE_FIELD_CONTRACTS = {
    "HEAD": {"paramType"},
    "TEMPLATE": {"customTailOutputConfig", "historyJsonInputStr", "historyJsonOutputStr", "historyMsgStr", "historyMsgType", "historyMsgVariables", "inputHistoryMsgStr", "inputHistoryMsgType", "inputHistoryMsgVariables", "isCustomHistoryMsg", "isCustomTailJsonOutput", "isCustomTailOutput", "isHistoryJsonInput", "isHistoryJsonOutput", "isJsonOutput", "isStreamingOutput", "output"},
    "INTERMEDIATE_OUTPUT": {"historyMsgStr", "historyMsgType", "historyMsgVariables", "isCustomHistoryMsg"},
    "MODEL": {"apiBase", "context", "defaultOutput", "enableThinking", "fallback", "ignoreException", "retry", "errorStrategy", "model", "modelConfig", "output", "outputFormat", "params", "prompt", "reasoningMode", "thinkingMode"},
    "AGENT": {"agentMode", "context", "defaultOutput", "enableThinking", "fallback", "ignoreException", "retry", "errorStrategy", "knlToolList", "model", "modelConfig", "output", "outputFormat", "params", "prompt", "thinkingMode", "toolChoiceOnly", "tools"},
    "AI_PLUGIN": {"body", "header", "output", "path", "pluginKey", "pluginName", "query", "requireBodyContentType", "toolKey", "toolName", "urlMethod"},
    "API_PLUGIN": {"body", "header", "output", "path", "pluginKey", "pluginName", "query", "requireBodyContentType", "urlMethod"},
    "MCP": {"auth", "body", "header", "mcpServerKey", "mcpServerName", "name", "output", "query", "requireBodyContentType", "toolKey", "toolName", "urlMethod"},
    "WORKFLOW": {"input", "output", "workflowKey", "workflowName"},
    "NEW_KNOWLEDGE": {"appName", "params", "recallToolConfig", "recallTools", "serviceCode", "serviceConfig"},
    "CODE": {"code", "input", "language", "output"},
    "JUDGE": {"conditionList"},
    "LOOP": {"edges", "loopInput", "loopVariables", "nodes", "output", "validateStatus"},
    "LOOP_START": {"loopInput"},
    "LOOP_OUTPUT": {"customTailOutputConfig", "output", "resetLoopVariables"},
}

TYPE_ALIASES = {
    "str": "STRING", "string": "STRING", "text": "STRING", "text-input": "STRING", "paragraph": "STRING",
    "int": "INTEGER", "integer": "INTEGER", "long": "INTEGER",
    "float": "NUMBER", "double": "NUMBER", "number": "NUMBER",
    "bool": "BOOLEAN", "boolean": "BOOLEAN", "checkbox": "BOOLEAN",
    "dict": "OBJECT", "map": "OBJECT", "json_object": "OBJECT", "object": "OBJECT",
    "list": "ARRAY", "tuple": "ARRAY", "set": "ARRAY", "array": "ARRAY",
    "array<object>": "ARRAY", "array<string>": "ARRAY", "array[number]": "ARRAY",
    "json": "JSON", "any": "ANY", "unknown": "ANY",
}


def walk(value: Any, path: list[Any] | None = None, depth: int = 0) -> Iterator[tuple[list[Any], Any]]:
    if depth > MAX_DEPTH:
        raise ValueError("DSL nesting depth exceeds scanner limit")
    path = path or []
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from walk(item, [*path, key], depth + 1)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk(item, [*path, index], depth + 1)


def pointer(parts: list[Any]) -> str:
    return "/" + "/".join(str(part).replace("~", "~0").replace("/", "~1") for part in parts)


def _load(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_DSL_BYTES:
        raise ValueError(f"DSL exceeds {MAX_DSL_BYTES} byte limit")
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError("JSON DSL root must be an object")
    return payload


def _validate_envelope(document: dict[str, Any]) -> None:
    schema_path = Path(__file__).resolve().parents[2] / "schemas" / "workflow-envelope.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(document), key=lambda item: list(item.absolute_path))
    if errors:
        first = errors[0]
        location = pointer(list(first.absolute_path)) or "/"
        raise ValueError(f"JSON DSL envelope schema violation at {location}: {first.message}")


def _extract_graph(document: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if isinstance(document.get("nodes"), list) and isinstance(document.get("edges"), list):
        return document, "direct_graph"
    body = document.get("body")
    if isinstance(body, dict) and isinstance(body.get("body"), dict):
        graph = body["body"]
        if isinstance(graph.get("nodes"), list) and isinstance(graph.get("edges"), list):
            return graph, "api_body_body"
    workflow = document.get("workflow")
    if isinstance(workflow, dict) and isinstance(workflow.get("graph"), dict):
        return workflow["graph"], "workflow_graph"
    raise ValueError("Expected nodes/edges in root, body.body, or workflow.graph")


def _normalized_type(raw: str) -> NodeType:
    return NODE_TYPES.get(raw.strip().upper(), NodeType.UNKNOWN)


def _text(value: Any) -> str:
    return "\n".join(item for _, item in walk(value) if isinstance(item, str))


def _contains_secret(value: str) -> bool:
    return bool(SECRET_RE.search(value)) and not bool(PLACEHOLDER_RE.search(value))


def _method(config: dict[str, Any]) -> str:
    return str(config.get("urlMethod") or config.get("method") or "").upper()


def _structured_output(config: dict[str, Any]) -> bool:
    output = config.get("output")
    return bool(
        (str(config.get("outputFormat") or "").lower() in {"json", "object"})
        or (str(config.get("outputType") or "").lower() in {"object", "array<object>"} and isinstance(output, list) and output)
        or config.get("isJsonOutput") is True
    )


def _contract_type(value: Any) -> str | None:
    raw = str(value or "").strip().lower().replace(" ", "")
    if not raw:
        return None
    if raw.startswith("array[") or raw.startswith("array<") or raw.endswith("[]"):
        return "ARRAY"
    return TYPE_ALIASES.get(raw, raw.upper())


def _compatible_types(producer: str | None, consumer: str | None) -> bool:
    if not producer or not consumer or "ANY" in {producer, consumer}:
        return True
    if producer == consumer:
        return True
    if {producer, consumer} <= {"INTEGER", "NUMBER"}:
        return True
    if producer == "JSON" and consumer in {"JSON", "OBJECT", "ARRAY"}:
        return True
    if consumer == "JSON" and producer in {"OBJECT", "ARRAY"}:
        return True
    return False


def _schema_entry(entries: Any, name: str) -> dict[str, Any] | None:
    if not isinstance(entries, list):
        return None
    normalized = name.replace("[]", "")
    return next(
        (item for item in entries if isinstance(item, dict) and str(item.get("name") or item.get("variable") or "") == normalized),
        None,
    )


def _schema_path_type(entries: Any, path: str) -> str | None:
    parts = [part for part in path.split(".") if part]
    current = entries
    result: str | None = None
    for index, part in enumerate(parts):
        item = _schema_entry(current, part)
        if not item:
            return None
        result = _contract_type(item.get("type") or item.get("valueType") or item.get("value_type"))
        if index < len(parts) - 1:
            current = item.get("sub") if isinstance(item.get("sub"), list) else item.get("children")
    return result


def _producer_reference_type(node: Node, variable_path: str) -> str | None:
    if node.type == NodeType.INPUT.value:
        return _schema_path_type(node.config.get("paramList"), variable_path)
    if node.original_type == "LOOP_START":
        return _schema_path_type(node.config.get("loopInput"), variable_path)
    if variable_path:
        nested = _schema_path_type(node.config.get("output"), variable_path)
        if nested:
            return nested
    declared = _contract_type(node.config.get("outputType"))
    if declared:
        return declared
    output = node.config.get("output")
    if isinstance(output, list) and len(output) == 1 and isinstance(output[0], dict):
        return _contract_type(output[0].get("type"))
    return None


def _expression_types(expression: ast.AST | None, assignments: dict[str, set[str]]) -> set[str]:
    if expression is None:
        return {"NULL"}
    if isinstance(expression, ast.Dict):
        return {"OBJECT"}
    if isinstance(expression, (ast.List, ast.Tuple, ast.Set, ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        return {"ARRAY"}
    if isinstance(expression, ast.Constant):
        if expression.value is None:
            return {"NULL"}
        if isinstance(expression.value, bool):
            return {"BOOLEAN"}
        if isinstance(expression.value, str):
            return {"STRING"}
        if isinstance(expression.value, int):
            return {"INTEGER"}
        if isinstance(expression.value, float):
            return {"NUMBER"}
    if isinstance(expression, ast.JoinedStr):
        return {"STRING"}
    if isinstance(expression, (ast.Compare, ast.BoolOp)):
        return {"BOOLEAN"}
    if isinstance(expression, ast.Name):
        return set(assignments.get(expression.id, {"ANY"}))
    if isinstance(expression, ast.IfExp):
        return _expression_types(expression.body, assignments) | _expression_types(expression.orelse, assignments)
    if isinstance(expression, ast.BinOp):
        left = _expression_types(expression.left, assignments)
        right = _expression_types(expression.right, assignments)
        if "STRING" in left or "STRING" in right:
            return {"STRING"}
        if (left | right) <= {"INTEGER", "NUMBER"}:
            return {"NUMBER" if "NUMBER" in left | right else "INTEGER"}
    if isinstance(expression, ast.Call):
        name = _call_name(expression.func)
        if name in {"json.loads", "orjson.loads"}:
            return {"JSON"}
        if name in {"json.dumps", "orjson.dumps", "str", "repr"}:
            return {"STRING"}
        if name in {"dict"}:
            return {"OBJECT"}
        if name in {"list", "tuple", "set"}:
            return {"ARRAY"}
        if name in {"bool"}:
            return {"BOOLEAN"}
        if name in {"int"}:
            return {"INTEGER"}
        if name in {"float"}:
            return {"NUMBER"}
    return {"ANY"}


def _python_return_types(code: str) -> set[str]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()
    functions = [item for item in tree.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in {"handler", "main"}]
    targets = functions or [tree]
    assignments: dict[str, set[str]] = defaultdict(set)
    for target in targets:
        for item in ast.walk(target):
            if isinstance(item, (ast.Assign, ast.AnnAssign)):
                value = item.value
                names: list[str] = []
                if isinstance(item, ast.Assign):
                    names = [candidate.id for candidate in item.targets if isinstance(candidate, ast.Name)]
                elif isinstance(item.target, ast.Name):
                    names = [item.target.id]
                inferred = _expression_types(value, assignments)
                for name in names:
                    assignments[name].update(inferred)
    returns: set[str] = set()
    for target in targets:
        for item in ast.walk(target):
            if isinstance(item, ast.Return):
                returns.update(_expression_types(item.value, assignments))
    return returns


def _tool_spec(raw: dict[str, Any], owner: str, parent: str | None = None) -> dict[str, Any]:
    cfg = raw.get("toolParamConfig") if isinstance(raw.get("toolParamConfig"), dict) else raw
    params: list[dict[str, Any]] = []
    for location in ("query", "body", "header", "path", "input"):
        values = cfg.get(location, []) if isinstance(cfg, dict) else []
        if isinstance(values, dict):
            values = [values]
        for item in values if isinstance(values, list) else []:
            if isinstance(item, dict):
                params.append({
                    "location": location,
                    "name": str(item.get("name") or ""),
                    "required": bool(item.get("required") or item.get("isRequired")),
                    "disabled": item.get("disabled"),
                    "agent_visible": item.get("canAgentSee"),
                    "variable_type": str(item.get("variableType") or ""),
                    "value": item.get("variable") if item.get("variable") not in (None, "") else item.get("value"),
                })
    kind = str(raw.get("type") or "UNKNOWN").lower()
    method = str(cfg.get("method") or raw.get("urlMethod") or "").upper() if isinstance(cfg, dict) else ""
    return {
        "owner_node_id": owner,
        "key": str(raw.get("key") or raw.get("toolKey") or raw.get("pluginKey") or raw.get("mcpServerKey") or raw.get("workflowKey") or ""),
        "parent_key": parent,
        "kind": kind,
        "method": method,
        "version": raw.get("versionCount") or raw.get("aiPluginVersionCount"),
        "source": raw.get("source"),
        "auth_declared": isinstance(raw.get("auth"), list) and bool(raw.get("auth")),
        "auth_present": "auth" in raw,
        "parameters": params,
        "has_output_schema": bool(cfg.get("output")) if isinstance(cfg, dict) else False,
        "raw_name": str(raw.get("toolName") or raw.get("pluginName") or raw.get("mcpServerName") or raw.get("workflowName") or ""),
    }


def _collect_tool_specs(config: dict[str, Any], node_id: str, raw_type: str) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    if raw_type in {"AI_PLUGIN", "API_PLUGIN", "MCP", "WORKFLOW"}:
        specs.append(_tool_spec(config, node_id))
    for raw in config.get("tools", []) if isinstance(config.get("tools"), list) else []:
        if not isinstance(raw, dict):
            continue
        top = _tool_spec(raw, node_id)
        specs.append(top)
        for child in raw.get("toolList", []) if isinstance(raw.get("toolList"), list) else []:
            if isinstance(child, dict):
                specs.append(_tool_spec(child, node_id, top["key"]))
    return specs


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _python_code_capabilities(code: str) -> set[str]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {"CODE_PARSE_ERROR"}
    calls = {_call_name(item.func) for item in ast.walk(tree) if isinstance(item, ast.Call)}
    capabilities: set[str] = set()
    families = {
        "CODE_DYNAMIC_EXEC": {"eval", "exec", "compile", "__import__", "importlib.import_module"},
        "CODE_PROCESS": {"os.system", "os.popen", "subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"},
        "CODE_NETWORK": {"requests", "urllib", "http.client", "socket", "aiohttp", "httpx"},
        "CODE_FILE_IO": {"open", "io.open", "pathlib.Path.open", "pathlib.Path.read_text", "pathlib.Path.write_text", "pathlib.Path.read_bytes", "pathlib.Path.write_bytes"},
    }
    for capability, prefixes in families.items():
        if any(any(call == prefix or call.startswith(prefix + ".") for prefix in prefixes) for call in calls):
            capabilities.add(capability)
    if capabilities:
        capabilities.add("DANGEROUS_CODE_PRIMITIVE")
    return capabilities


def _classify(node_type: NodeType, raw_type: str, config: dict[str, Any], specs: list[dict[str, Any]]) -> tuple[list[str], bool, bool, bool]:
    capabilities: set[str] = set()
    external = False
    effectful = False
    high = False
    identity = f"{raw_type} {config.get('label', '')} {config.get('description', '')}".lower()
    if node_type == NodeType.INPUT:
        capabilities.add("UNTRUSTED_INPUT")
    elif node_type == NodeType.OUTPUT:
        capabilities.add("OUTPUT_BOUNDARY")
    elif node_type == NodeType.KNOWLEDGE:
        capabilities.add("KNOWLEDGE_READ")
    elif node_type == NodeType.LLM:
        capabilities.add("MODEL_INFERENCE")
    elif node_type == NodeType.AGENT:
        capabilities.update({"MODEL_INFERENCE", "AUTONOMOUS_PLANNING"})
    elif node_type == NodeType.CODE:
        capabilities.add("SANDBOXED_CODE")
        code = str(config.get("code") or "")
        language = str(config.get("language") or "python").lower()
        if language in {"python", "py", "python3"}:
            capabilities.update(_python_code_capabilities(code))
        else:
            capabilities.add("CODE_LANGUAGE_UNSUPPORTED")
        if "DANGEROUS_CODE_PRIMITIVE" in capabilities:
            effectful = high = True
    if node_type in {NodeType.TOOL, NodeType.AGENT}:
        for spec in specs:
            kind = spec["kind"]
            method = spec["method"]
            if kind == "mcp":
                capabilities.add("MCP_TOOL")
            elif kind == "workflow":
                capabilities.add("SUBWORKFLOW")
            elif kind in {"ai_plugin", "api_plugin"}:
                capabilities.add("PLUGIN_TOOL")
            elif kind == "multi_modal":
                capabilities.add("MULTIMODAL_MODEL")
            else:
                capabilities.add("UNKNOWN_TOOL_CAPABILITY")
            if kind in {"mcp", "workflow", "ai_plugin", "api_plugin"}:
                external = True
            if method and method not in {"GET", "HEAD", "OPTIONS"}:
                capabilities.add("NETWORK_WRITE")
                effectful = True
            elif method in {"GET", "HEAD", "OPTIONS"}:
                capabilities.add("NETWORK_READ")
        if any(word in identity for word in HIGH_IMPACT_WORDS):
            high = effectful = True
        if node_type == NodeType.AGENT and effectful:
            high = True
    return sorted(capabilities), external, effectful, high


def _graph_path(adjacency: dict[str, set[str]], source: str, target: str) -> bool:
    queue = deque([source])
    seen = {source}
    while queue:
        current = queue.popleft()
        if current == target:
            return True
        for nxt in adjacency.get(current, set()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return False


def parse_workflow(path: Path) -> tuple[WorkflowIR, dict[str, Any]]:
    document = _load(path)
    _validate_envelope(document)
    graph, source_shape = _extract_graph(document)
    nodes: list[Node] = []
    edges: list[Edge] = []
    gaps: list[dict[str, Any]] = []
    reference_type_checks: list[dict[str, Any]] = []
    code_return_contracts: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    def parse_graph(item: dict[str, Any], base: list[Any], scope: str, container: str | None = None) -> None:
        raw_nodes = item.get("nodes", [])
        raw_edges = item.get("edges", [])
        if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
            gaps.append({"pointer": pointer(base), "reason": "nodes_or_edges_not_array"})
            return
        if len(nodes) + len(raw_nodes) > MAX_NODES:
            raise ValueError(f"DSL contains more than {MAX_NODES} nodes")
        local_ids = {str(raw.get("id")) for raw in raw_nodes if isinstance(raw, dict) and raw.get("id") is not None}
        for index, raw in enumerate(raw_nodes):
            location = [*base, "nodes", index]
            if not isinstance(raw, dict):
                gaps.append({"pointer": pointer(location), "reason": "node_not_object"})
                continue
            node_id = str(raw.get("id") or f"missing-{scope}-{index}")
            if node_id in seen_ids:
                gaps.append({"node_id": node_id, "pointer": pointer(location), "reason": "duplicate_node_id"})
                continue
            seen_ids.add(node_id)
            config = raw.get("data") if isinstance(raw.get("data"), dict) else {}
            raw_type = str(config.get("type") or raw.get("type") or "UNKNOWN").upper()
            mapped = _normalized_type(raw_type)
            specs = _collect_tool_specs(config, node_id, raw_type)
            capabilities, external, effectful, high = _classify(mapped, raw_type, config, specs)
            node = Node(
                id=node_id,
                original_type=raw_type,
                type=mapped.value,
                title=str(config.get("label") or config.get("name") or node_id),
                json_pointer=pointer(location),
                config=config,
                container_id=container,
                capabilities=capabilities,
                tool_specs=specs,
                external=external,
                effectful=effectful,
                high_impact=high,
            )
            nodes.append(node)
            if mapped == NodeType.CODE and str(config.get("language") or "python").lower() in {"python", "py", "python3"}:
                inferred_types = sorted(_python_return_types(str(config.get("code") or "")))
                declared_type = _contract_type(config.get("outputType"))
                incompatible = bool(
                    declared_type
                    and inferred_types
                    and all(item not in {"ANY", "NULL"} for item in inferred_types)
                    and any(not _compatible_types(item, declared_type) for item in inferred_types)
                )
                code_return_contracts.append({
                    "node_id": node_id,
                    "pointer": f"{pointer(location)}/data/outputType",
                    "declared_type": declared_type,
                    "inferred_types": inferred_types,
                    "compatible": not incompatible,
                })
            if mapped == NodeType.UNKNOWN:
                gaps.append({"node_id": node_id, "pointer": pointer(location), "reason": "unsupported_node_type", "original_type": raw_type})
            else:
                recognized = COMMON_NODE_FIELDS | NODE_FIELD_CONTRACTS.get(raw_type, set())
                for field in sorted(set(config) - recognized):
                    gaps.append({"node_id": node_id, "pointer": f"{pointer(location)}/data/{field}", "reason": "unmapped_node_field", "field": field, "original_type": raw_type})
            if raw_type == "LOOP" and isinstance(config.get("nodes"), list):
                parse_graph(config, [*location, "data"], f"loop:{node_id}", node_id)
        all_ids = seen_ids | local_ids
        for index, raw in enumerate(raw_edges):
            location = [*base, "edges", index]
            if not isinstance(raw, dict):
                gaps.append({"pointer": pointer(location), "reason": "edge_not_object"})
                continue
            source, target = str(raw.get("source") or ""), str(raw.get("target") or "")
            edge = Edge(
                id=str(raw.get("id") or stable_id("EDGE", scope, source, target, index)),
                source=source,
                target=target,
                source_handle=raw.get("sourceHandle"),
                target_handle=raw.get("targetHandle"),
                source_index=raw.get("sourceIndex") if isinstance(raw.get("sourceIndex"), int) else None,
                scope=scope,
            )
            edges.append(edge)
            if not source or not target or source not in all_ids or target not in all_ids:
                gaps.append({"edge_id": edge.id, "pointer": pointer(location), "reason": "dangling_edge", "source": source, "target": target})

    parse_graph(graph, [], "root")
    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        adjacency[edge.source].add(edge.target)
    symbol_producers: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        output_name = node.config.get("outputName")
        if isinstance(output_name, str) and output_name:
            symbol_producers[output_name].append(node.id)
        # The platform exports loop inputs with the stable symbolic producer
        # name ``loopStart`` rather than the generated LOOP_START node id.
        # Keep this as an explicit dialect binding; do not guess aliases for
        # arbitrary node-id prefixes.
        if node.original_type == "LOOP_START":
            symbol_producers["loopStart"].append(node.id)
    node_ids = {node.id for node in nodes}
    node_map = {node.id: node for node in nodes}
    refs: list[VariableRef] = []

    def choose_candidates(candidates: list[str], consumer: Node) -> list[str]:
        if len(candidates) > 1 and consumer.container_id:
            scoped = [item for item in candidates if node_map[item].container_id == consumer.container_id]
            if scoped:
                candidates = scoped
        if len(candidates) > 1:
            reachable = [item for item in candidates if _graph_path(adjacency, item, consumer.id)]
            if len(reachable) == 1:
                candidates = reachable
        return candidates

    def add_resolved(producer_id: str, variable_path: str, consumer: Node, location: str, field: str, resolution: str, expected_type: Any = None) -> None:
        refs.append(VariableRef(producer_id, variable_path, consumer.id, location, field, resolution))
        producer_type = _producer_reference_type(node_map[producer_id], variable_path)
        consumer_type = _contract_type(expected_type)
        if producer_type and consumer_type:
            reference_type_checks.append({
                "producer_node_id": producer_id,
                "consumer_node_id": consumer.id,
                "variable_path": variable_path,
                "consumer_field": field,
                "pointer": location,
                "producer_type": producer_type,
                "consumer_type": consumer_type,
                "compatible": _compatible_types(producer_type, consumer_type),
            })

    def resolve(symbol: str, consumer: Node, location: str, field: str, expected_type: Any = None) -> None:
        if not symbol:
            return
        if symbol in node_ids:
            add_resolved(symbol, "", consumer, location, field, "node_id", expected_type)
            return
        if "." in symbol:
            prefix, variable = symbol.split(".", 1)
            if prefix in node_ids:
                add_resolved(prefix, variable, consumer, location, field, "explicit", expected_type)
                return
            candidates = choose_candidates(list(symbol_producers.get(prefix, [])), consumer)
            if len(candidates) == 1:
                add_resolved(candidates[0], variable, consumer, location, field, "symbol_path", expected_type)
                return
            if len(candidates) > 1:
                for candidate in candidates:
                    refs.append(VariableRef(candidate, variable, consumer.id, location, field, "ambiguous"))
                gaps.append({"node_id": consumer.id, "pointer": location, "reason": "ambiguous_symbol", "symbol": symbol, "producers": candidates})
                return
        candidates = choose_candidates(list(symbol_producers.get(symbol, [])), consumer)
        if len(candidates) == 1:
            add_resolved(candidates[0], "", consumer, location, field, "symbol", expected_type)
        elif len(candidates) > 1:
            for candidate in candidates:
                refs.append(VariableRef(candidate, "", consumer.id, location, field, "ambiguous"))
            gaps.append({"node_id": consumer.id, "pointer": location, "reason": "ambiguous_symbol", "symbol": symbol, "producers": candidates})
        else:
            gaps.append({"node_id": consumer.id, "pointer": location, "reason": "unresolved_symbol", "symbol": symbol})

    for node in nodes:
        local_params: dict[str, str] = {}
        for key in ("params", "input", "output", "body", "query", "header", "loopInput"):
            values = node.config.get(key, [])
            if isinstance(values, dict):
                values = [values]
            for index, item in enumerate(values if isinstance(values, list) else []):
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "")
                raw_value = item.get("variable") if item.get("variable") not in (None, "") else item.get("value")
                location = f"{node.json_pointer}/data/{key}/{index}"
                if str(item.get("variableType") or "").upper() == "REFERENCE":
                    if isinstance(raw_value, str) and raw_value:
                        resolve(raw_value, node, location, name.lower(), item.get("type") or item.get("valueType") or item.get("value_type"))
                        if name:
                            local_params[name] = raw_value
                    elif item.get("required") is True or item.get("isRequired") is True:
                        gaps.append({"node_id": node.id, "pointer": location, "reason": "required_reference_unbound", "field": name})
        # AGENT tool registries can contain the same reference objects several
        # levels below tools[].toolList[].toolParamConfig.  They are part of
        # the data-flow contract even though they are not top-level params.
        tools_value = node.config.get("tools")
        if isinstance(tools_value, list):
            for parts, item in walk(tools_value):
                if not isinstance(item, dict) or str(item.get("variableType") or "").upper() != "REFERENCE":
                    continue
                raw_value = item.get("variable") if item.get("variable") not in (None, "") else item.get("value")
                if not isinstance(raw_value, str) or not raw_value:
                    continue
                location = f"{node.json_pointer}/data{pointer(['tools', *parts])}"
                resolve(raw_value, node, location, str(item.get("name") or "tool_parameter").lower(), item.get("type") or item.get("valueType") or item.get("value_type"))
        for case_index, case in enumerate(node.config.get("conditionList", []) if isinstance(node.config.get("conditionList"), list) else []):
            for cond_index, condition in enumerate(case.get("subConditions", []) if isinstance(case, dict) else []):
                if not isinstance(condition, dict):
                    continue
                symbol = str(condition.get("name") or "")
                location = f"{node.json_pointer}/data/conditionList/{case_index}/subConditions/{cond_index}"
                if symbol:
                    resolve(symbol, node, location, "condition")
                elif str(condition.get("variableType") or "").upper() == "REFERENCE":
                    gaps.append({"node_id": node.id, "pointer": location, "reason": "condition_reference_unbound"})
        prompt = str(node.config.get("prompt") or "")
        for match in re.finditer(r"\$\{([^}]+)\}", prompt):
            name = match.group(1).strip()
            location = f"{node.json_pointer}/data/prompt"
            if name in local_params:
                resolve(local_params[name], node, location, "prompt")
            elif name in symbol_producers or "." in name:
                resolve(name, node, location, "prompt")
            else:
                gaps.append({"node_id": node.id, "pointer": location, "reason": "unresolved_prompt_parameter", "symbol": name})
        if node.type == NodeType.CODE.value:
            for match in re.finditer(r"params\.get\(\s*['\"]([^'\"]+)['\"]", str(node.config.get("code") or "")):
                name = match.group(1)
                # ``params.get('x')`` is a local lookup, not a global workflow
                # symbol.  It only contributes a data-flow edge when the CODE
                # node's input contract explicitly binds x to a producer.
                if name in local_params:
                    resolve(local_params[name], node, f"{node.json_pointer}/data/code", "code_parameter")

    by_consumer: dict[str, list[VariableRef]] = defaultdict(list)
    for ref in refs:
        by_consumer[ref.consumer_node_id].append(ref)
    for node in nodes:
        node.variable_refs = by_consumer.get(node.id, [])

    secrets = [pointer(path_parts) for path_parts, value in walk(document) if isinstance(value, str) and _contains_secret(value)]
    ir = WorkflowIR(
        workflow_id=str(graph.get("id") or path.stem),
        workflow_hash=file_sha256(path),
        source_shape=source_shape,
        nodes=nodes,
        edges=edges,
        variable_refs=refs,
        coverage_gaps=gaps,
        raw_metadata={
            "source_file": path.name,
            "root_node_count": len(graph.get("nodes", [])),
            "ir_node_count": len(nodes),
            "edge_count": len(edges),
            "container_count": sum(node.type == NodeType.LOOP.value for node in nodes),
            "tool_spec_count": sum(len(node.tool_specs) for node in nodes),
            "secret_locations": secrets,
            "input_contract_present": any(node.type == NodeType.INPUT.value and isinstance(node.config.get("paramList"), list) and node.config.get("paramList") for node in nodes),
            "dialect_contract": "internal-json-workflow/observed-2026-08",
            "observed_node_field_count": sum(len(node.config) for node in nodes),
            "unmapped_node_field_count": sum(gap.get("reason") == "unmapped_node_field" for gap in gaps),
            "history_context_config": graph.get("historyContextConfig") if isinstance(graph.get("historyContextConfig"), dict) else {},
            "reference_type_checks": reference_type_checks,
            "reference_type_mismatches": [item for item in reference_type_checks if not item["compatible"]],
            "code_return_contracts": code_return_contracts,
            "code_return_mismatches": [item for item in code_return_contracts if not item["compatible"]],
        },
    )
    return ir, document
