from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
import re

import yaml

from .models import Fact, Finding, Node, NodeType, Severity, Status, WorkflowIR, stable_id


SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
STATUS_RANK = {"MITIGATED": 0, "COVERAGE_GAP": 1, "CANDIDATE": 2, "OBSERVED": 3, "PROBABLE": 4, "CONFIRMED": 5}
SENSITIVE_WORDS = {"password", "secret", "token", "credential", "authorization", "phone", "email", "account", "customer", "userid", "user_id", "身份证", "手机号", "客户", "账号", "密钥"}
DANGEROUS_ARGUMENT_WORDS = {"url", "uri", "host", "endpoint", "command", "cmd", "sql", "query", "path", "file", "projectid", "apiid", "userid", "resourceid", "tenantid"}
INSTRUCTION_GUARDS = {"untrusted", "treat as data", "do not follow", "ignore instructions", "不可信", "仅作为数据", "不得执行", "忽略其中指令"}
LIMIT_KEYS = {"maxnewtoken", "maxtoken", "maxtokenlimit", "maxiterations", "max_steps", "timeout", "loopcount", "maxloopcount"}
FALLBACK_KEYS = {"fallback", "retry", "errorstrategy", "onerror", "failclosed", "degradation"}
CONTROL_WORDS = {"validate", "policy", "authorize", "approval", "guard", "审核", "授权", "校验", "审批"}
AFFIRMATIVE_GATE_WORDS = {"allow", "approve", "approved", "authorize", "authorized", "permit", "pass", "success", "true", "通过", "批准", "已授权", "允许", "成功"}
GATE_SUBJECT_WORDS = {"approve", "approval", "authorize", "authorization", "permission", "privilege", "role", "owner", "tenant", "policy", "allow", "valid", "审批", "授权", "权限", "角色", "归属", "租户", "策略", "校验", "有效"}
ELSE_HANDLES = {"else", "default", "false", "otherwise", "否则", "默认"}
UNTRUSTED_SOURCE_TYPES = {NodeType.INPUT.value, NodeType.KNOWLEDGE.value, NodeType.LLM.value, NodeType.AGENT.value, NodeType.TOOL.value}
WORKFLOW_GAP_DOMAINS = {"identity_authorization", "resilience_budget", "supply_chain", "data_protection", "output_safety", "authorization_boundary"}

REMEDIATIONS = {
    "structure_coverage": ["修复重复节点、悬空边和未知节点绑定后重新扫描。"],
    "data_contract": ["为每个引用提供唯一生产者、明确类型和可追溯 JSON Pointer。"],
    "input_contract": ["在入口声明类型、必填、长度、数量、枚举和文件约束。"],
    "instruction_boundary": ["把不可信内容放入明确的数据通道，并在高优先级指令中声明不可执行其指令。"],
    "untrusted_content_boundary": ["对检索和工具输出保留来源、执行注入检测，并在到达模型/工具前验证。"],
    "action_authorization": ["在高后果能力前加入不可绕过的授权、参数约束或业务所需人工确认。"],
    "identity_authorization": ["在运行时验证调用身份、对象归属、租户范围和最小权限。"],
    "structured_data_contract": ["使用封闭字段集的结构化输出 Schema，并在下游执行前严格验证。"],
    "execution_boundary": ["移除动态执行原语，或在隔离沙盒中使用固定代码和严格输入白名单。"],
    "egress_control": ["对协议、域名、端口、路径和重定向执行出站白名单。"],
    "resilience_budget": ["配置超时、次数/令牌预算、幂等、熔断、补偿和失败关闭。"],
    "data_protection": ["分类敏感字段，执行最小化、脱敏、访问控制和出站策略。"],
    "supply_chain": ["固定可信版本并验证工具、插件、MCP 和子工作流的来源与完整性。"],
    "agent_governance": ["限制 Agent 目标、工具集合和迭代，并提供运行时不可拦截的停止机制。"],
    "knowledge_governance": ["固定知识范围，执行租户 ACL、来源追踪、阈值和检索数量边界。"],
    "output_contract": ["为最终输出声明并验证稳定 Schema，拒绝额外或类型错误字段。"],
    "output_safety": ["按渲染上下文净化富文本、链接和远程资源。"],
    "workflow_boundary": ["验证子工作流输入输出、委派身份、版本和失败语义。"],
    "tool_contract": ["从受信注册表补充工具能力、参数、输出和副作用元数据。"],
}


def _flatten_keys(value: Any) -> set[str]:
    result: set[str] = set()
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, child in current.items():
                result.add(str(key).lower())
                stack.append(child)
        elif isinstance(current, list):
            stack.extend(current)
    return result


def _contains_words(value: Any, words: Iterable[str]) -> bool:
    text = str(value).lower()
    return any(word.lower() in text for word in words)


def _declares_structured_output(node: Node) -> bool:
    """Return whether the DSL claims an object/JSON-style output.

    A declared format is deliberately different from a *strict* schema.  The
    distinction is important for model-to-tool flows: ``outputFormat: json``
    alone does not constrain field names, nested values, or extra properties.
    """
    return bool(
        node.config.get("isJsonOutput") is True
        or str(node.config.get("outputFormat") or "").lower() in {"json", "object"}
        or str(node.config.get("outputType") or "").lower() in {"object", "array<object>"}
    )


def _output_schema_issues(entries: Any, *, path: str = "output") -> list[str]:
    """Validate the exported field-level contract used as a strict boundary."""
    if not isinstance(entries, list) or not entries:
        return [f"{path} 缺少字段列表"]
    issues: list[str] = []
    names: set[str] = set()
    for index, item in enumerate(entries):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            issues.append(f"{item_path} 不是字段对象")
            continue
        name = str(item.get("name") or item.get("variable") or "").strip()
        raw_type = str(item.get("type") or item.get("valueType") or item.get("value_type") or "").strip().lower()
        if not name:
            issues.append(f"{item_path} 缺少字段名")
        elif name in names:
            issues.append(f"{path} 存在重复字段 {name}")
        else:
            names.add(name)
        if not raw_type:
            issues.append(f"{item_path} 缺少字段类型")
            continue
        if raw_type in {"any", "unknown", "json"}:
            issues.append(f"{item_path} 使用未封闭类型 {raw_type}")
            continue
        if raw_type in {"object", "dict", "map", "array<object>", "array< object >"}:
            children = item.get("sub") if isinstance(item.get("sub"), list) else item.get("children")
            if not isinstance(children, list) or not children:
                issues.append(f"{item_path} 的对象值缺少嵌套字段 Schema")
            else:
                issues.extend(_output_schema_issues(children, path=f"{item_path}.sub"))
    return issues


def _has_strict_structured_contract(node: Node) -> bool:
    return _declares_structured_output(node) and not _output_schema_issues(node.config.get("output"))


def _declares_free_text_output(node: Node) -> bool:
    return (
        str(node.config.get("outputFormat") or "").strip().lower() in {"text", "string", "markdown", "html"}
        or str(node.config.get("outputType") or "").strip().lower() in {"text", "string"}
    )


def _schema_issue_is_explicit_malformed(entries: Any) -> bool:
    """Only malformed exported entries are deterministic errors; omitted schema is a gap."""
    if not isinstance(entries, list) or not entries:
        return False
    names: set[str] = set()
    for item in entries:
        if not isinstance(item, dict):
            return True
        name = str(item.get("name") or item.get("variable") or "").strip()
        raw_type = str(item.get("type") or item.get("valueType") or item.get("value_type") or "").strip()
        if not name or not raw_type or name in names:
            return True
        names.add(name)
    return False


def _normalise_handle(value: Any) -> int | str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit() or (text.startswith("-") and text[1:].isdigit()):
        return int(text)
    return text.lower()


def _edge_condition_handle(edge: Any, handles: list[int | str | None]) -> int | str | None:
    """Resolve a condition edge using only exported handles or ordinal mapping."""
    raw_handle = str(edge.source_handle or "").strip().lower()
    if raw_handle in ELSE_HANDLES:
        return raw_handle
    match = re.search(r"-(\d+)$", raw_handle)
    encoded = int(match.group(1)) if match else None
    if encoded is not None and encoded in handles:
        return encoded
    if isinstance(edge.source_index, int):
        if edge.source_index in handles:
            return edge.source_index
        if 0 <= edge.source_index < len(handles):
            return handles[edge.source_index]
    return encoded


def _case_is_affirmative(case: dict[str, Any]) -> bool:
    """Recognise a successful, action-related predicate without fixing its value vocabulary."""
    conditions = case.get("subConditions")
    if not isinstance(conditions, list):
        return False
    for condition in conditions:
        if not isinstance(condition, dict):
            continue
        value = condition.get("value")
        if value in (None, False, "", [], {}):
            continue
        if value is True:
            return True
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in AFFIRMATIVE_GATE_WORDS:
                return True
        subject = " ".join(
            str(condition.get(field) or "")
            for field in ("name", "field", "variable", "left")
        ).lower()
        operator = str(condition.get("condition") or condition.get("operator") or "").strip().lower()
        if operator and any(word in subject for word in GATE_SUBJECT_WORDS):
            return True
    return False


def _high_trust_output(node: Node) -> bool:
    keys = _flatten_keys(node.config)
    text = f"{node.title} {node.config}".lower()
    return bool(
        keys.intersection({"machineconsumed", "machine_consumed", "decisionoutput", "decision_output", "verifiedanswer", "verified_answer", "requiresverifiedresult", "requires_verified_result"})
        or any(word in text for word in ("自动决策", "授权结果", "审批结果", "verified answer", "machine consumed"))
    )


def _citation_required(node: Node) -> bool:
    keys = _flatten_keys(node.config)
    text = f"{node.title} {node.config}".lower()
    return bool(
        keys.intersection({"requires_citations", "requirecitations", "verified_answer", "requiresources"})
        or any(word in text for word in ("引用", "来源", "citation", "references", "verified answer"))
    )


@dataclass(frozen=True)
class ImpactContext:
    executable: bool
    reaches_model: bool
    reaches_external: bool
    reaches_effectful: bool
    reaches_high_impact: bool
    reaches_output: bool
    reaches_high_trust_output: bool
    machine_consumed: bool
    has_untrusted_upstream: bool
    has_sensitive_upstream: bool

    @property
    def consequential(self) -> bool:
        return self.reaches_effectful or self.reaches_high_impact or self.reaches_high_trust_output


def _input_variables(node: Node) -> list[dict[str, Any]]:
    values = node.config.get("paramList", [])
    return [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []


def _positive_int_like(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value > 0
    return isinstance(value, str) and value.strip().isdigit() and int(value.strip()) > 0


def _unit_score_like(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    try:
        score = float(value)
    except (TypeError, ValueError):
        return False
    return 0 <= score <= 1


def _sensitive(node: Node) -> bool:
    # Sensitivity is a data-contract property, not a bag-of-words property over
    # the entire node.  Scanning arbitrary configuration keys makes operational
    # controls such as ``maxNewToken`` look like credential-bearing data.
    semantic_parts: list[str] = [node.title, str(node.config.get("outputName") or "")]
    for collection_name in ("paramList", "params", "output", "body", "header"):
        collection = node.config.get(collection_name)
        if not isinstance(collection, list):
            continue
        stack = list(collection)
        while stack:
            item = stack.pop()
            if not isinstance(item, dict):
                continue
            semantic_parts.extend(
                str(item.get(field) or "")
                for field in ("name", "label", "description", "classification", "dataClassification")
            )
            for child_key in ("sub", "children"):
                children = item.get(child_key)
                if isinstance(children, list):
                    stack.extend(children)
    for field in ("classification", "dataClassification", "sensitivity", "pii"):
        value = node.config.get(field)
        if value not in (None, False, "", [], {}):
            semantic_parts.append(str(value))
    text = " ".join(semantic_parts).lower()
    return any(word in text for word in SENSITIVE_WORDS)


def _is_object_type(raw_type: str) -> bool:
    return raw_type.strip().lower() in {"object", "dict", "map", "json_object"}


def _has_object_schema(item: dict[str, Any]) -> bool:
    children = item.get("sub") if isinstance(item.get("sub"), list) else item.get("children")
    return isinstance(children, list) and bool(children)


def _has_input_boundary(item: dict[str, Any], raw_type: str) -> bool:
    """Accept a positive upper bound or a non-empty allow-list, never a min alone."""
    lowered = {str(key).lower(): value for key, value in item.items()}
    for key, value in lowered.items():
        if any(token in key for token in ("max", "limit", "maxlength", "maxitems", "maxcount", "maxsize")) and _positive_int_like(value):
            return True
        if any(token in key for token in ("option", "enum", "allow")) and isinstance(value, (list, tuple, set, dict)) and bool(value):
            return True
    return False


def _has_file_constraints(item: dict[str, Any]) -> bool:
    lowered = {str(key).lower(): value for key, value in item.items()}

    def restrictive_type_value(value: Any) -> bool:
        values = list(value.values()) if isinstance(value, dict) else list(value) if isinstance(value, (list, tuple, set)) else [value]
        normalized = [str(item).strip().lower() for item in values if str(item).strip()]
        return bool(normalized) and any(item not in {"*", "*/*"} for item in normalized)

    mime_or_extension = any(
        any(token in key for token in ("mime", "accept", "extension", "filetype", "contenttype", "allowedtype"))
        and restrictive_type_value(value)
        for key, value in lowered.items()
    )
    has_size = any(
        any(token in key for token in ("maxsize", "filesize", "size_limit", "sizelimit")) and _positive_int_like(value)
        for key, value in lowered.items()
    )
    is_multiple = lowered.get("multiple") is True or lowered.get("allowmultiple") is True
    has_count = any(
        any(token in key for token in ("maxcount", "maxfiles", "filecount")) and _positive_int_like(value)
        for key, value in lowered.items()
    )
    return mime_or_extension and has_size and (not is_multiple or has_count)


def _has_sensitive_input_handling(item: dict[str, Any], node: Node) -> bool:
    declared = {"classification", "dataclassification", "sensitivity", "pii", "retention", "ttl", "redaction", "masking", "minimize", "minimization"}
    stack = [item, node.config]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, value in current.items():
                if str(key).lower() in declared and value not in (None, False, "", [], {}):
                    return True
                stack.append(value)
        elif isinstance(current, list):
            stack.extend(current)
    return False


class GraphIndex:
    def __init__(self, ir: WorkflowIR) -> None:
        self.nodes = ir.node_map()
        self.control: dict[str, set[str]] = defaultdict(set)
        self.data: dict[str, set[str]] = defaultdict(set)
        self.out_edges: dict[str, list[Any]] = defaultdict(list)
        for edge in ir.edges:
            if edge.source in self.nodes and edge.target in self.nodes:
                self.control[edge.source].add(edge.target)
                self.out_edges[edge.source].append(edge)
        for ref in ir.variable_refs:
            if ref.producer_node_id in self.nodes and ref.consumer_node_id in self.nodes:
                self.data[ref.producer_node_id].add(ref.consumer_node_id)

    def path(self, source: str, target: str, *, data_only: bool = False, control_only: bool = False, excluded: set[str] | None = None) -> list[str] | None:
        excluded = excluded or set()
        if source in excluded or target in excluded:
            return None
        if data_only and control_only:
            raise ValueError("data_only and control_only are mutually exclusive")
        adjacency = self.data if data_only else self.control if control_only else {key: self.control[key] | self.data[key] for key in self.nodes}
        queue: deque[list[str]] = deque([[source]])
        seen = {source}
        while queue:
            path = queue.popleft()
            if path[-1] == target:
                return path
            if len(path) > 64:
                continue
            for nxt in adjacency.get(path[-1], set()):
                if nxt not in seen and nxt not in excluded:
                    seen.add(nxt)
                    queue.append([*path, nxt])
        return None

    def any_path(self, sources: Iterable[Node], targets: Iterable[Node], *, data_only: bool = False, control_only: bool = False, excluded: set[str] | None = None) -> list[str] | None:
        for source in sources:
            for target in targets:
                found = self.path(source.id, target.id, data_only=data_only, control_only=control_only, excluded=excluded)
                if found:
                    return found
        return None

    def reachable(self, sources: Iterable[str], *, reverse: bool = False) -> set[str]:
        adjacency: dict[str, set[str]] = defaultdict(set)
        for source, targets in self.control.items():
            for target in targets:
                adjacency[target if reverse else source].add(source if reverse else target)
        seen = {item for item in sources if item in self.nodes}
        queue = deque(seen)
        while queue:
            current = queue.popleft()
            for nxt in adjacency.get(current, set()):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        return seen


class RuleCatalog:
    def __init__(self, path: Path) -> None:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules = payload.get("rules", []) if isinstance(payload, dict) else []
        self.rules = {str(item["id"]): item for item in rules if isinstance(item, dict) and item.get("id")}
        required = {"id", "title", "severity", "detectability", "control_domain", "standards"}
        for rule_id, rule in self.rules.items():
            missing = required - set(rule)
            if missing:
                raise ValueError(f"Rule {rule_id} missing metadata: {sorted(missing)}")
        bindings_path = path.parent / "json-dsl-bindings.yml"
        binding_payload = yaml.safe_load(bindings_path.read_text(encoding="utf-8"))
        self.bindings: dict[str, dict[str, Any]] = {}
        duplicate: set[str] = set()
        for binding in binding_payload.get("bindings", []):
            for rule_id in binding.get("rule_ids", []):
                rule_id = str(rule_id)
                if rule_id in self.bindings:
                    duplicate.add(rule_id)
                self.bindings[rule_id] = {key: value for key, value in binding.items() if key != "rule_ids"}
        missing = set(self.rules) - set(self.bindings)
        unknown = set(self.bindings) - set(self.rules)
        if duplicate or missing or unknown:
            raise ValueError(f"Rule binding mismatch duplicate={sorted(duplicate)} missing={sorted(missing)} unknown={sorted(unknown)}")
        applicability_path = path.parent / "rule-applicability.yml"
        applicability_payload = yaml.safe_load(applicability_path.read_text(encoding="utf-8"))
        self.applicability: dict[str, dict[str, Any]] = {}
        applicability_duplicates: set[str] = set()
        required_policy = {"name", "path_requirement", "impact_floor", "absence_handling", "default_report_group", "exclusions"}
        for policy in applicability_payload.get("policies", []):
            if not isinstance(policy, dict):
                continue
            missing_policy = required_policy - set(policy)
            if missing_policy:
                raise ValueError(f"Applicability policy missing metadata: {sorted(missing_policy)}")
            for rule_id in policy.get("rule_ids", []):
                rule_id = str(rule_id)
                if rule_id in self.applicability:
                    applicability_duplicates.add(rule_id)
                self.applicability[rule_id] = {key: value for key, value in policy.items() if key != "rule_ids"}
        applicability_missing = set(self.rules) - set(self.applicability)
        applicability_unknown = set(self.applicability) - set(self.rules)
        if applicability_duplicates or applicability_missing or applicability_unknown:
            raise ValueError(
                "Rule applicability mismatch "
                f"duplicate={sorted(applicability_duplicates)} missing={sorted(applicability_missing)} unknown={sorted(applicability_unknown)}"
            )

    def get(self, rule_id: str) -> dict[str, Any]:
        return self.rules[rule_id]


class SecurityEngine:
    def __init__(self, ir: WorkflowIR, catalog: RuleCatalog) -> None:
        self.ir = ir
        self.catalog = catalog
        self.graph = GraphIndex(ir)
        self.facts: list[Fact] = []
        self.findings: list[Finding] = []
        self.raw_matches: list[dict[str, Any]] = []
        self._dedupe: set[tuple[str, tuple[str, ...], str]] = set()
        self._impact_cache: dict[str, ImpactContext] = {}

    def impact(self, node: Node) -> ImpactContext:
        cached = self._impact_cache.get(node.id)
        if cached:
            return cached
        entries = [item for item in self.ir.nodes if item.type == NodeType.INPUT.value]
        outputs = [item for item in self.ir.nodes if item.type == NodeType.OUTPUT.value]
        downstream = [item for item in self.ir.nodes if item.id != node.id and self.graph.path(node.id, item.id)]
        upstream_data = [item for item in self.ir.nodes if item.id != node.id and self.graph.path(item.id, node.id, data_only=True)]
        control_from_entry = self.graph.any_path(entries, [node], control_only=True) if entries else None
        control_to_output = self.graph.any_path([node], outputs, control_only=True) if outputs else None
        executable = bool((not entries or control_from_entry) and (not outputs or control_to_output))
        context = ImpactContext(
            executable=executable,
            reaches_model=any(item.type in {NodeType.LLM.value, NodeType.AGENT.value} for item in downstream),
            reaches_external=any(item.external for item in downstream),
            reaches_effectful=any(item.effectful for item in downstream),
            reaches_high_impact=any(item.high_impact for item in downstream),
            reaches_output=any(item.type == NodeType.OUTPUT.value for item in downstream),
            reaches_high_trust_output=any(item.type == NodeType.OUTPUT.value and _high_trust_output(item) for item in downstream),
            machine_consumed=any(item.type in {NodeType.CONDITION.value, NodeType.CODE.value, NodeType.TOOL.value, NodeType.AGENT.value} for item in downstream),
            has_untrusted_upstream=any(item.type in UNTRUSTED_SOURCE_TYPES for item in upstream_data),
            has_sensitive_upstream=any(_sensitive(item) for item in upstream_data),
        )
        self._impact_cache[node.id] = context
        return context

    def _reference_field_names(self, ref: Any) -> set[str]:
        names = {str(ref.consumer_field or "").lower(), str(ref.variable_name or "").lower()}
        producer = self.graph.nodes.get(ref.producer_node_id)
        if not producer or producer.type != NodeType.INPUT.value:
            return names
        root = str(ref.variable_name or "").split(".", 1)[0]
        variables = producer.config.get("paramList")
        if not isinstance(variables, list):
            return names
        entries = variables if not root else [
            item for item in variables
            if isinstance(item, dict) and str(item.get("name") or item.get("variable") or "") == root
        ]
        if not entries:
            return names
        stack = list(entries)
        while stack:
            current = stack.pop()
            if not isinstance(current, dict):
                continue
            names.add(str(current.get("name") or current.get("variable") or "").lower())
            for key in ("sub", "children"):
                value = current.get(key)
                if isinstance(value, list):
                    stack.extend(value)
        return names

    def untrusted_refs(self, node: Node, field_words: Iterable[str] = ()) -> list[Any]:
        words = tuple(word.lower() for word in field_words)
        refs = []
        for ref in node.variable_refs:
            producer = self.graph.nodes.get(ref.producer_node_id)
            if not producer or producer.type not in UNTRUSTED_SOURCE_TYPES:
                continue
            fields = self._reference_field_names(ref)
            if words and not any(word in field for word in words for field in fields):
                continue
            refs.append(ref)
        return refs

    def emit(self, rule_id: str, node_ids: list[str], message: str, *, status: Status, severity: Severity | None = None, confidence: float = 1.0, evidence: list[str] | None = None, missing_context: list[str] | None = None, report_group: str | None = None, remediation: list[str] | None = None) -> None:
        key = (rule_id, tuple(node_ids), message)
        if key in self._dedupe:
            return
        self._dedupe.add(key)
        rule = self.catalog.get(rule_id)
        locations = [self.graph.nodes[node_id].json_pointer for node_id in node_ids if node_id in self.graph.nodes]
        fact_id = stable_id("FACT", rule_id, *node_ids, message)
        self.facts.append(Fact(fact_id, rule_id, node_ids, evidence or locations, {"message": message}))
        self.findings.append(Finding(
            id=stable_id("FINDING", rule_id, *node_ids, message),
            rule_id=rule_id,
            title=str(rule["title"]),
            status=status.value,
            severity=(severity.value if severity else str(rule["severity"])),
            confidence=confidence,
            node_ids=node_ids,
            evidence_refs=[fact_id],
            dsl_locations=locations,
            message=message,
            remediation=remediation or REMEDIATIONS.get(str(rule["control_domain"]), ["补充确定性控制并重新验证。"]),
            standards=[str(item) for item in rule.get("standards", [])],
            missing_context=missing_context or [],
            dynamic_test=rule.get("dynamic_test"),
            anchor_node_id=node_ids[-1] if node_ids else None,
            control_domain=str(rule["control_domain"]),
            report_group=report_group or (
                "coverage_gap" if status == Status.COVERAGE_GAP
                else str(rule.get("report_group") or self.catalog.applicability[rule_id].get("default_report_group") or "risk")
            ),
        ))

    def run(self) -> tuple[list[Fact], list[Finding], dict[str, Any]]:
        self._structure_rules()
        for node in self.ir.nodes:
            if node.type == NodeType.INPUT.value:
                self._input_rules(node)
            elif node.type in {NodeType.LLM.value, NodeType.AGENT.value}:
                self._model_rules(node)
            if node.type in {NodeType.TOOL.value, NodeType.AGENT.value, NodeType.CODE.value}:
                self._tool_rules(node)
            if node.type == NodeType.KNOWLEDGE.value:
                self._knowledge_rules(node)
            if node.type == NodeType.OUTPUT.value:
                self._output_rules(node)
            if node.type in {NodeType.OUTPUT.value, NodeType.LLM.value, NodeType.AGENT.value, NodeType.TOOL.value, NodeType.CODE.value}:
                self._output_schema_rules(node)
            if node.type == NodeType.CONDITION.value:
                self._condition_rules(node)
            if node.type == NodeType.LOOP.value:
                self._loop_rules(node)
        self._cross_rules()
        self.raw_matches = [{
            "match_id": stable_id("MATCH", item.id),
            "finding_id_before_aggregation": item.id,
            "rule_id": item.rule_id,
            "node_ids": item.node_ids,
            "status": item.status,
            "severity": item.severity,
            "evidence_refs": item.evidence_refs,
        } for item in self.findings]
        aggregated = self._aggregate(self.findings)
        aggregated.sort(key=lambda item: (-SEVERITY_RANK.get(item.severity, -1), item.rule_id, item.id))
        candidates = {
            "rule_count": len(self.catalog.rules),
            "raw_match_count": len(self.raw_matches),
            "raw_matches": self.raw_matches,
            "candidate_count": len(aggregated),
            "candidates": [{
                "candidate_id": stable_id("CANDIDATE", item.id),
                "finding_id": item.id,
                "rule_id": item.rule_id,
                "node_ids": item.node_ids,
                "recommended_status": item.status,
                "recommended_severity": item.severity,
                "binding": self.catalog.bindings[item.rule_id],
                "applicability": self.catalog.applicability[item.rule_id],
            } for item in aggregated],
        }
        return self.facts, aggregated, candidates

    def _structure_rules(self) -> None:
        for gap in self.ir.coverage_gaps:
            reason = str(gap.get("reason") or "")
            node_ids = [str(gap["node_id"])] if gap.get("node_id") in self.graph.nodes else []
            evidence = [str(gap.get("pointer"))] if gap.get("pointer") else []
            if reason in {"duplicate_node_id", "dangling_edge", "nodes_or_edges_not_array"}:
                self.emit("FLOW-001", node_ids, f"图结构错误：{reason}。", status=Status.CONFIRMED, evidence=evidence)
            elif reason == "unsupported_node_type":
                self.emit("FLOW-002", node_ids, f"未知节点类型 {gap.get('original_type')} 未进入确定性能力映射。", status=Status.COVERAGE_GAP, evidence=evidence, missing_context=["需要该节点的导出契约和运行语义。"])
            elif reason == "unmapped_node_field":
                self.emit("FLOW-002", node_ids, f"节点字段 {gap.get('field')} 尚未进入版本化字段契约。", status=Status.COVERAGE_GAP, evidence=evidence, missing_context=["需要确认字段运行语义和安全影响。"])
            elif reason in {"ambiguous_symbol", "unresolved_symbol", "required_reference_unbound", "condition_reference_unbound", "unresolved_prompt_parameter"}:
                status = Status.CONFIRMED if reason == "required_reference_unbound" else Status.COVERAGE_GAP
                self.emit("FLOW-003", node_ids, f"引用问题：{reason}（{gap.get('symbol') or gap.get('field') or 'unknown'}）。", status=status, evidence=evidence)
        for mismatch in self.ir.raw_metadata.get("reference_type_mismatches", []):
            producer_id = str(mismatch.get("producer_node_id") or "")
            consumer_id = str(mismatch.get("consumer_node_id") or "")
            if producer_id not in self.graph.nodes or consumer_id not in self.graph.nodes:
                continue
            consumer = self.graph.nodes[consumer_id]
            consequential = self.impact(consumer).consequential
            path = str(mismatch.get("variable_path") or self.graph.nodes[producer_id].config.get("outputName") or "输出")
            message = (
                f"引用 {path} 的生产者类型为 {mismatch.get('producer_type')}，"
                f"消费者字段 {mismatch.get('consumer_field') or 'input'} 声明为 {mismatch.get('consumer_type')}。"
            )
            self.emit(
                "FLOW-017", [producer_id, consumer_id], message,
                status=Status.CONFIRMED,
                severity=Severity.HIGH if consequential else Severity.MEDIUM,
                evidence=[str(mismatch.get("pointer") or consumer.json_pointer)],
                report_group="risk" if consequential else "posture",
                remediation=[f"将 {consumer.title} 的输入类型调整为与上游一致，或在进入该节点前增加显式且可验证的类型转换。"],
            )
        starts = [node.id for node in self.ir.nodes if node.type in {NodeType.INPUT.value, NodeType.STRUCTURAL.value} and node.original_type != "LOOP_OUTPUT"]
        ends = [node.id for node in self.ir.nodes if node.type == NodeType.OUTPUT.value or node.original_type == "LOOP_OUTPUT"]
        from_start = self.graph.reachable(starts)
        to_end = self.graph.reachable(ends, reverse=True)
        for node in self.ir.nodes:
            if node.type in {NodeType.INPUT.value, NodeType.OUTPUT.value, NodeType.STRUCTURAL.value, NodeType.LOOP.value}:
                continue
            missing = []
            if node.id not in from_start:
                missing.append("入口不可达")
            if ends and node.id not in to_end:
                missing.append("无法到达输出")
            if missing:
                self.emit("FLOW-013", [node.id], f"节点不在完整可执行路径上：{'、'.join(missing)}。节点本地配置仍会审核，但跨节点攻击链不应假定可执行。", status=Status.OBSERVED, severity=Severity.LOW, report_group="posture")
        history = self.ir.raw_metadata.get("history_context_config", {})
        history = history if isinstance(history, dict) else {}
        local_history_nodes = [
            node for node in self.ir.nodes
            if str(node.config.get("context") or "").lower() in {"session", "history", "memory"}
            or any(key.startswith("history") or key.startswith("ishistory") for key in _flatten_keys(node.config))
        ]
        history_enabled = history.get("enableHistory") is True or bool(local_history_nodes)
        policy_keys = _flatten_keys(history)
        for item in local_history_nodes:
            policy_keys.update(_flatten_keys(item.config))
        if history_enabled and not policy_keys.intersection({"retention", "ttl", "sessionisolation", "tenant", "redaction", "maxmessages", "maxtokens", "max_tokens"}):
            node_ids = [item.id for item in local_history_nodes]
            self.emit("FLOW-015", node_ids, "工作流启用了历史或会话上下文，但未导出会话隔离、保留期限、脱敏或容量边界。", status=Status.COVERAGE_GAP, missing_context=["session_isolation", "retention_policy", "history_redaction"])

    def _input_rules(self, node: Node) -> None:
        variables = _input_variables(node)
        if not variables:
            self.emit("IN-001", [node.id], "入口未导出 paramList，无法验证业务输入 Schema。", status=Status.COVERAGE_GAP, missing_context=["入口字段可能由调用 API 或平台表单另行声明。"])
            return
        for item in variables:
            name = str(item.get("name") or item.get("variable") or "unnamed")
            raw_type = str(item.get("type") or "")
            if not raw_type:
                self.emit("IN-001", [node.id], f"输入字段 {name} 缺少类型。", status=Status.CONFIRMED)
                continue
            if _is_object_type(raw_type) and not _has_object_schema(item):
                self.emit("IN-001", [node.id], f"对象输入字段 {name} 未导出子字段 Schema，无法验证允许的键和嵌套类型。", status=Status.COVERAGE_GAP, missing_context=["input_object_schema"])
            if raw_type.lower() in {"string", "text", "array", "array<object>", "array<string>", "array<number>"} and not _has_input_boundary(item, raw_type):
                self.emit("IN-002", [node.id], f"输入字段 {name} 未声明长度、数量或枚举边界。", status=Status.OBSERVED)
            if "file" in raw_type.lower():
                if not _has_file_constraints(item):
                    self.emit("IN-003", [node.id], f"文件字段 {name} 的类型或大小约束不完整。", status=Status.CONFIRMED)
            if any(word in name.lower() for word in SENSITIVE_WORDS) and not _has_sensitive_input_handling(item, node):
                self.emit("IN-005", [node.id], f"入口字段 {name} 具有敏感数据语义，DSL 未声明分类或最小化策略。", status=Status.COVERAGE_GAP, missing_context=["data_classification"])

    def _model_rules(self, node: Node) -> None:
        prompt = str(node.config.get("prompt") or "")
        impact = self.impact(node)
        input_refs = [
            ref for ref in node.variable_refs
            if self.graph.nodes.get(ref.producer_node_id)
            and self.graph.nodes[ref.producer_node_id].type == NodeType.INPUT.value
            and ref.consumer_field.lower() == "prompt"
        ]
        if input_refs and not _contains_words(prompt, INSTRUCTION_GUARDS):
            self.emit("IN-004", [input_refs[0].producer_node_id, node.id], "入口数据进入模型 Prompt，未发现明确的不可信数据边界。", status=Status.OBSERVED)
            self.emit("LLM-001", [input_refs[0].producer_node_id, node.id], "Prompt 未声明用户内容不能覆盖系统目标或触发未授权动作。", status=Status.OBSERVED)
        if self.ir.raw_metadata.get("secret_locations") and any(location.startswith(node.json_pointer) for location in self.ir.raw_metadata["secret_locations"]):
            self.emit("LLM-002", [node.id], "模型节点包含疑似真实密钥或授权材料。", status=Status.CONFIRMED)
        keys = _flatten_keys(node.config.get("modelConfig", {}))
        if (node.type == NodeType.AGENT.value or impact.consequential) and not keys.intersection(LIMIT_KEYS):
            self.emit("LLM-004", [node.id], "模型节点未导出令牌、步骤或迭代预算。", status=Status.COVERAGE_GAP, missing_context=["platform_model_budget"])
        if (node.type == NodeType.AGENT.value or impact.consequential) and not _flatten_keys(node.config).intersection(FALLBACK_KEYS):
            self.emit("LLM-005", [node.id], "模型失败、超时和降级策略未出现在 DSL 中。", status=Status.COVERAGE_GAP, missing_context=["runtime_fallback_policy"])
        api_base = str(node.config.get("apiBase") or "").strip()
        if api_base.lower().startswith("http://"):
            self.emit("LLM-007", [node.id], "模型服务 apiBase 明确使用 HTTP；是否由可信内部网关终止 TLS 需要运行时确认。", status=Status.OBSERVED, severity=Severity.LOW, missing_context=["trusted_tls_terminator", "model_egress_policy"], report_group="posture")
        if api_base and ("${" in api_base or "{{" in api_base):
            self.emit("LLM-007", [node.id], "模型服务 apiBase 可由动态表达式控制。", status=Status.PROBABLE, confidence=0.9, missing_context=["model_endpoint_allowlist"])
        if node.type == NodeType.AGENT.value:
            effectful = [spec for spec in node.tool_specs if spec.get("method") and spec["method"] not in {"GET", "HEAD", "OPTIONS"}]
            has_containment = bool(_flatten_keys(node.config).intersection({"goal_lock", "allowed_goals", "kill_switch", "stop_conditions", "maxiterations", "max_steps"}))
            incoming = self.graph.any_path([item for item in self.ir.nodes if item.type == NodeType.INPUT.value], [node])
            if incoming and effectful and not has_containment:
                self.emit("FLOW-012", incoming, f"Agent 注册 {len(node.tool_specs)} 个能力且包含副作用工具，未导出目标锁定或停止边界。", status=Status.PROBABLE, confidence=0.86, missing_context=["runtime_goal_lock", "out_of_band_kill_switch"])

    def _tool_rules(self, node: Node) -> None:
        impact = self.impact(node)
        if node.type == NodeType.CODE.value:
            code_kinds = [item for item in ("CODE_DYNAMIC_EXEC", "CODE_PROCESS", "CODE_NETWORK", "CODE_FILE_IO") if item in node.capabilities]
            if code_kinds:
                severity = Severity.CRITICAL if "CODE_DYNAMIC_EXEC" in code_kinds else Severity.HIGH
                self.emit("TOOL-004", [node.id], f"内嵌代码调用危险原语类别：{', '.join(code_kinds)}。", status=Status.CONFIRMED, severity=severity)
            if "CODE_PARSE_ERROR" in node.capabilities:
                self.emit("TOOL-011", [node.id], "声明为 Python 的代码无法通过 AST 语法解析，危险原语覆盖不完整。", status=Status.COVERAGE_GAP, missing_context=["platform_code_wrapper_semantics"])
            if "CODE_LANGUAGE_UNSUPPORTED" in node.capabilities:
                self.emit("TOOL-011", [node.id], f"代码语言 {node.config.get('language')} 尚无确定性语法适配器。", status=Status.COVERAGE_GAP, missing_context=["language_specific_parser"])
            if not node.config.get("output") and impact.consequential:
                self.emit("TOOL-006", [node.id], "CODE 节点未导出字段级输出 Schema；固定代码本身不因此被视为注入。", status=Status.COVERAGE_GAP, missing_context=["code_output_contract"])
            return_contract = next(
                (item for item in self.ir.raw_metadata.get("code_return_mismatches", []) if item.get("node_id") == node.id),
                None,
            )
            if return_contract:
                consequential = impact.consequential
                inferred = ", ".join(return_contract.get("inferred_types", [])) or "未知"
                self.emit(
                    "TOOL-013", [node.id],
                    f"Python 返回类型推断为 {inferred}，但节点 outputType 声明为 {return_contract.get('declared_type')}。",
                    status=Status.CONFIRMED,
                    severity=Severity.HIGH if consequential else Severity.MEDIUM,
                    evidence=[str(return_contract.get("pointer") or node.json_pointer)],
                    report_group="risk" if consequential else "posture",
                    remediation=[f"修正 {node.title} 的 outputType/字段 Schema，或让所有返回分支稳定返回声明类型；随后重新校验下游引用。"],
                )
            return
        specs = node.tool_specs
        if not specs:
            self.emit("TOOL-001", [node.id], "工具或 Agent 未导出可解析的能力规格。", status=Status.COVERAGE_GAP)
            return
        unknown = [spec for spec in specs if spec["kind"] in {"", "unknown"}]
        if unknown:
            self.emit("TOOL-001", [node.id], "存在无法分类的工具能力。", status=Status.CANDIDATE)
        effectful = [spec for spec in specs if spec["method"] and spec["method"] not in {"GET", "HEAD", "OPTIONS"}]
        dangerous_refs = self.untrusted_refs(node, DANGEROUS_ARGUMENT_WORDS)
        if (effectful or node.high_impact) and dangerous_refs:
            names = sorted({ref.consumer_field for ref in dangerous_refs if ref.consumer_field})
            self.emit("TOOL-002", [*sorted({ref.producer_node_id for ref in dangerous_refs}), node.id], f"副作用或高影响工具的安全敏感参数受不可信数据控制：{', '.join(names) or 'dynamic argument'}。", status=Status.PROBABLE, confidence=0.88)
        target_refs = self.untrusted_refs(node, ("url", "uri", "host", "endpoint", "callback"))
        if target_refs and (node.external or "NETWORK_READ" in node.capabilities or "NETWORK_WRITE" in node.capabilities):
            self.emit("TOOL-003", [*sorted({ref.producer_node_id for ref in target_refs}), node.id], "外部目标参数由不可信数据控制，DSL 未声明协议、域名、端口和重定向白名单。", status=Status.PROBABLE, confidence=0.9, missing_context=["runtime_egress_policy"])
        auth_unknown = [spec for spec in specs if spec["kind"] in {"mcp", "api_plugin", "ai_plugin", "workflow"} and not spec["auth_declared"]]
        authorization_relevant = node.effectful or node.high_impact or bool(dangerous_refs) or impact.has_sensitive_upstream
        if auth_unknown and authorization_relevant:
            self.emit("TOOL-005", [node.id], "工具身份、租户或对象级授权不能从导出 DSL 验证。", status=Status.COVERAGE_GAP, missing_context=["runtime_iam", "object_level_authorization"])
        output_contract_relevant = impact.reaches_model or impact.reaches_effectful or impact.reaches_high_impact or impact.reaches_high_trust_output
        if output_contract_relevant and any(not spec["has_output_schema"] for spec in specs if spec["kind"] not in {"multi_modal"}):
            self.emit("TOOL-006", [node.id], "至少一个工具未导出可验证的输出 Schema。", status=Status.COVERAGE_GAP, missing_context=["tool_registry_output_schema"])
        if effectful and not _flatten_keys(node.config).intersection({"timeout", "retry", "idempotency", "compensation", "circuit_breaker"}):
            self.emit("TOOL-007", [node.id], "副作用工具未导出超时、重试、幂等或补偿配置。", status=Status.COVERAGE_GAP, missing_context=["runtime_resilience_policy"])
        supply_chain_relevant = node.external and impact.executable and (node.effectful or node.high_impact or impact.reaches_model or impact.has_sensitive_upstream)
        if supply_chain_relevant and any(spec["kind"] in {"mcp", "api_plugin", "ai_plugin", "workflow"} and not spec.get("version") for spec in specs):
            self.emit("TOOL-008", [node.id], "工具/MCP/子工作流缺少版本固定；完整性签名也不在 DSL 中。", status=Status.COVERAGE_GAP, missing_context=["registry_signature", "artifact_digest"])
        elif supply_chain_relevant and specs and not _flatten_keys(node.config).intersection({"digest", "sha256", "signature", "integrity"}):
            self.emit("TOOL-008", [node.id], "工具版本可见，但来源签名或内容摘要不可验证。", status=Status.COVERAGE_GAP, missing_context=["registry_signature", "artifact_digest"])
        if effectful and node.type == NodeType.AGENT.value:
            self.emit("TOOL-010", [node.id], "自主 Agent 可选择副作用工具，DSL 未提供不可绕过的动作授权门。", status=Status.PROBABLE, confidence=0.84, missing_context=["runtime_action_policy"])
        if any(spec["kind"] == "workflow" for spec in specs):
            message = (
                "Agent 可调用子工作流，但委派身份、被调输入契约和失败语义不在 DSL 中。"
                if node.type == NodeType.AGENT.value
                else "子工作流调用未导出被调输入输出契约、委派身份或失败语义。"
            )
            self.emit("FLOW-011", [node.id], message, status=Status.COVERAGE_GAP, missing_context=["callee_contract", "delegated_identity"])
        if self.ir.raw_metadata.get("secret_locations") and any(location.startswith(node.json_pointer) for location in self.ir.raw_metadata["secret_locations"]):
            self.emit("TOOL-012", [node.id], "工具节点包含疑似真实密钥或授权材料。", status=Status.CONFIRMED)
        agent_visible_auth = [param for spec in specs for param in spec["parameters"] if param.get("agent_visible") is True and any(word in str(param.get("name") or "").lower() for word in ("authorization", "api-key", "apikey", "token", "secret"))]
        if agent_visible_auth:
            self.emit("TOOL-012", [node.id], "认证语义参数被标记为 Agent 可见；是否只暴露占位符不能从 DSL 确认。", status=Status.COVERAGE_GAP, missing_context=["runtime_credential_injection"])

    def _knowledge_rules(self, node: Node) -> None:
        impact = self.impact(node)
        configs = node.config.get("recallToolConfig")
        if not isinstance(configs, list):
            configs = node.config.get("recallTools", [])
        configs = configs if isinstance(configs, list) else []
        knowledge_codes = [str(item.get("knowledgeCode") or "").strip() for item in configs if isinstance(item, dict) and str(item.get("knowledgeCode") or "").strip()]
        dynamic_scope = any("${" in code or "{{" in code for code in knowledge_codes)
        if dynamic_scope:
            self.emit("KB-001", [node.id], "知识数据集标识可被动态表达式控制。", status=Status.CONFIRMED)
        if dynamic_scope or (len(set(knowledge_codes)) > 1 and _sensitive(node)):
            self.emit("KB-002", [node.id], "动态或敏感多数据集范围的租户 ACL 和业务过滤未出现在 DSL 中。", status=Status.COVERAGE_GAP, missing_context=["knowledge_acl", "tenant_filter"])
        service = node.config.get("serviceConfig") if isinstance(node.config.get("serviceConfig"), dict) else {}
        configured_counts = [service.get("recallCount"), *(item.get("reCallNum") for item in configs if isinstance(item, dict))]
        has_count = any(_positive_int_like(value) for value in configured_counts if value is not None)
        has_score = _unit_score_like(service.get("sortScore"))
        if (not has_count or not has_score) and (impact.consequential or _sensitive(node)):
            self.emit("KB-005", [node.id], "高影响或敏感知识路径的检索数量、相关性阈值未完整声明。", status=Status.COVERAGE_GAP, missing_context=["retrieval_limit", "retrieval_relevance_threshold"])
        valid_dataset = any(isinstance(item, dict) and str(item.get("knowledgeCode") or "").strip() for item in configs)
        if not valid_dataset:
            self.emit("KB-006", [node.id], "知识节点未导出固定的 knowledgeCode。", status=Status.CONFIRMED)
        invalid_counts = [value for value in configured_counts if value is not None and not _positive_int_like(value)]
        score = service.get("sortScore")
        if invalid_counts or (score is not None and not _unit_score_like(score)):
            self.emit("KB-006", [node.id], "知识检索数量或相关性阈值超出有效范围。", status=Status.CONFIRMED)

    def _output_rules(self, node: Node) -> None:
        if not _declares_structured_output(node):
            if _high_trust_output(node):
                self.emit("OUT-001", [node.id], "高信任或机器消费输出未声明可验证的结构化契约。", status=Status.PROBABLE, severity=Severity.MEDIUM, confidence=0.85, report_group="risk")
            else:
                self.emit("OUT-001", [node.id], "人工展示型输出未声明结构化契约；当前作为可靠性加固建议，不视为可利用漏洞。", status=Status.OBSERVED, severity=Severity.LOW, report_group="hardening")
        if node.original_type == "INTERMEDIATE_OUTPUT":
            self.emit("OUT-003", [node.id], "中间输出是额外披露边界，但受众和脱敏策略不在 DSL 中。", status=Status.COVERAGE_GAP, missing_context=["intermediate_output_audience", "redaction_policy"])
        output_format = str(node.config.get("outputFormat") or "").lower()
        explicit_rich_output = (
            output_format in {"html", "markdown"}
            or node.config.get("renderAsHtml") is True
            or node.config.get("renderLinks") is True
        )
        if explicit_rich_output:
            self.emit("OUT-004", [node.id], "输出明确启用富文本或链接渲染，净化策略不可验证。", status=Status.COVERAGE_GAP, missing_context=["renderer_sanitization"])

    def _output_schema_rules(self, node: Node) -> None:
        """Apply the same strict schema test to outputs produced by every node family."""
        if not _declares_structured_output(node):
            return
        issues = _output_schema_issues(node.config.get("output"))
        if issues:
            preview = "；".join(issues[:2])
            suffix = "；其余字段问题见 DSL 证据" if len(issues) > 2 else ""
            status = Status.CONFIRMED if _schema_issue_is_explicit_malformed(node.config.get("output")) else Status.COVERAGE_GAP
            missing_context = [] if status == Status.CONFIRMED else ["exported_output_schema"]
            self.emit("OUT-006", [node.id], f"节点声明结构化输出，但字段级 Schema 不完整：{preview}{suffix}。", status=status, missing_context=missing_context)

    def _condition_rules(self, node: Node) -> None:
        impact = self.impact(node)
        integrity_group = "risk" if impact.consequential else "posture"
        integrity_severity = None if impact.consequential else Severity.LOW
        cases = [item for item in node.config.get("conditionList", []) if isinstance(item, dict)] if isinstance(node.config.get("conditionList"), list) else []
        handles = [_normalise_handle(item.get("handleId")) for item in cases]
        outgoing = self.graph.out_edges.get(node.id, [])
        effective_handles: list[int | str | None] = []
        mismatches = []
        allowed = {handle for handle in handles if handle is not None}
        invalid_case_handles = len(handles) != len(cases) or len(allowed) != len(handles)
        for edge in outgoing:
            raw_handle = str(edge.source_handle or "").strip().lower()
            match = re.search(r"-(\d+)$", raw_handle)
            encoded = int(match.group(1)) if match else None
            ordinal_handle = handles[edge.source_index] if isinstance(edge.source_index, int) and 0 <= edge.source_index < len(handles) else None
            compatible = encoded == edge.source_index or (ordinal_handle is not None and encoded == ordinal_handle)
            if encoded is not None and edge.source_index is not None and not compatible:
                mismatches.append({"edge_id": edge.id, "sourceIndex": edge.source_index, "sourceHandleIndex": encoded})
            effective_handles.append(_edge_condition_handle(edge, handles))
        if invalid_case_handles:
            self.emit("FLOW-014", [node.id], "条件分支缺少 handleId 或存在重复 handleId，无法建立唯一的分支契约。", status=Status.CONFIRMED, severity=integrity_severity, report_group=integrity_group)
        elif len(handles) != len(set(handles)):
            self.emit("FLOW-014", [node.id], "条件分支存在重复 handleId。", status=Status.CONFIRMED, severity=integrity_severity, report_group=integrity_group)
        if mismatches:
            self.emit(
                "FLOW-014", [node.id],
                f"条件边的 sourceIndex 与 sourceHandle 既不满足句柄值对应，也不满足分支序号对应：{mismatches}。",
                status=Status.OBSERVED,
                severity=Severity.LOW,
                missing_context=["platform_branch_routing_precedence"],
                report_group="posture",
                remediation=["核对平台分支路由优先级，并让 sourceIndex 与 sourceHandle 通过同一个 handleId 或明确的分支序号映射表达。"],
            )
        invalid_edges = [item for item in effective_handles if item not in allowed and item not in ELSE_HANDLES]
        if invalid_edges:
            self.emit("FLOW-014", [node.id], f"出边 sourceIndex/sourceHandle 未对应任何已导出的条件或显式 ELSE：{sorted(set(invalid_edges), key=str)}。", status=Status.CONFIRMED, severity=integrity_severity, report_group=integrity_group)
        missing_edges = [item for item in handles if item not in effective_handles]
        if missing_edges or not outgoing:
            self.emit("FLOW-014", [node.id], "至少一个条件分支没有对应出边，或条件节点完全没有出边。", status=Status.OBSERVED, severity=integrity_severity, report_group=integrity_group)
        malformed = any(not item.get("subConditions") or any(not isinstance(cond, dict) or not cond.get("condition") or not cond.get("name") for cond in item.get("subConditions", [])) for item in cases)
        if malformed:
            self.emit("FLOW-014", [node.id], "条件表达式缺少变量、操作符或子条件。", status=Status.CONFIRMED, severity=integrity_severity, report_group=integrity_group)

    def _loop_rules(self, node: Node) -> None:
        keys = _flatten_keys(node.config)
        if not keys.intersection({"loopcount", "maxloopcount", "maxiterations", "timeout", "stopcondition", "breakcondition"}):
            children = [item for item in self.ir.nodes if item.container_id == node.id]
            resource_relevant = any(item.type in {NodeType.LLM.value, NodeType.AGENT.value} or item.effectful or item.high_impact for item in children) or self.impact(node).consequential
            if resource_relevant:
                self.emit("FLOW-007", [node.id], "包含模型或副作用能力的循环未导出最大次数、总时限或可验证终止条件。", status=Status.COVERAGE_GAP, missing_context=["runtime_iteration_limit"])
            else:
                self.emit("FLOW-007", [node.id], "普通循环未导出显式终止边界，作为资源加固建议。", status=Status.OBSERVED, severity=Severity.LOW, report_group="hardening")
        children = [item for item in self.ir.nodes if item.container_id == node.id]
        starts = [item for item in children if item.original_type == "LOOP_START"]
        ends = [item for item in children if item.original_type == "LOOP_OUTPUT"]
        if len(starts) != 1 or len(ends) != 1:
            self.emit("FLOW-016", [node.id], f"循环子图应有且仅有一个 LOOP_START 和 LOOP_OUTPUT，当前为 {len(starts)}/{len(ends)}。", status=Status.CONFIRMED)
        elif not self.graph.path(starts[0].id, ends[0].id):
            self.emit("FLOW-016", [node.id, starts[0].id, ends[0].id], "循环入口无法通过内部图到达循环输出。", status=Status.CONFIRMED)

    def _is_verified_action_gate_for_sink(self, node: Node, sink: Node) -> bool:
        """Recognise an action gate only when its *allow* branch exclusively leads to the sink.

        A name such as "approval" is not a control by itself.  We require a
        well-formed JUDGE node, an affirmative branch, and proof that no other
        branch of that JUDGE can reach the same side effect.  Runtime policy is
        still reported separately where the DSL cannot prove identity/object
        authorization.
        """
        if node.type != NodeType.CONDITION.value or not _contains_words(f"{node.title} {node.config}", CONTROL_WORDS):
            return False
        raw_cases = node.config.get("conditionList")
        cases = [item for item in raw_cases if isinstance(item, dict)] if isinstance(raw_cases, list) else []
        if not cases or len(cases) != len(raw_cases):
            return False
        handles = [_normalise_handle(item.get("handleId")) for item in cases]
        if any(handle is None for handle in handles) or len(set(handles)) != len(handles):
            return False
        affirmative = {handle for case, handle in zip(cases, handles) if _case_is_affirmative(case)}
        if not affirmative:
            return False
        branches_to_sink: list[int | str | None] = []
        for edge in self.graph.out_edges.get(node.id, []):
            if not self.graph.path(edge.target, sink.id, control_only=True):
                continue
            branch = _edge_condition_handle(edge, handles)
            if branch is None or branch in ELSE_HANDLES:
                return False
            branches_to_sink.append(branch)
        return bool(branches_to_sink) and all(branch in affirmative for branch in branches_to_sink)

    def _cross_rules(self) -> None:
        nodes = self.ir.nodes
        inputs = [item for item in nodes if item.type == NodeType.INPUT.value]
        knowledge = [item for item in nodes if item.type == NodeType.KNOWLEDGE.value]
        models = [item for item in nodes if item.type in {NodeType.LLM.value, NodeType.AGENT.value}]
        tools = [item for item in nodes if item.type in {NodeType.TOOL.value, NodeType.CODE.value} and (item.effectful or item.high_impact)]
        outputs = [item for item in nodes if item.type == NodeType.OUTPUT.value]
        for source in inputs:
            for sink in tools:
                controls = {item.id for item in nodes if self._is_verified_action_gate_for_sink(item, sink)}
                unguarded = self.graph.path(source.id, sink.id, control_only=True, excluded=controls)
                guarded = next((
                    [*first, *second[1:]]
                    for control_id in controls
                    if (first := self.graph.path(source.id, control_id, control_only=True))
                    and (second := self.graph.path(control_id, sink.id, control_only=True))
                ), None)
                direct_argument_control = bool(self.untrusted_refs(sink, DANGEROUS_ARGUMENT_WORDS))
                decisive_impact = sink.high_impact or direct_argument_control
                path_status = Status.CONFIRMED if decisive_impact else Status.PROBABLE
                path_confidence = 1.0 if decisive_impact else 0.8
                if unguarded and guarded:
                    self.emit("FLOW-006", unguarded, "副作用能力同时存在经过控制节点和绕过控制节点的可执行路径。", status=path_status, confidence=path_confidence, missing_context=[] if decisive_impact else ["runtime_action_authorization"])
                elif unguarded:
                    self.emit("FLOW-004", unguarded, "入口存在未经过确定性校验或授权节点到达副作用能力的可执行路径。", status=path_status, confidence=path_confidence, missing_context=[] if decisive_impact else ["runtime_action_authorization"])
        for kb in knowledge:
            for model in models:
                first = self.graph.path(kb.id, model.id, data_only=True)
                if not first:
                    continue
                prompt_bound = any(
                    ref.producer_node_id == kb.id
                    and ref.consumer_node_id == model.id
                    and ref.consumer_field.lower() == "prompt"
                    for ref in self.ir.variable_refs
                )
                if prompt_bound:
                    self.emit("KB-003", first, "知识内容被插入模型 Prompt；当前路径仅形成指令边界观察，若继续到达副作用能力再升级。", status=Status.OBSERVED, severity=Severity.LOW, confidence=0.9)
                for tool in tools:
                    second = self.graph.path(model.id, tool.id, data_only=True)
                    if second:
                        self.emit("FLOW-005", [*first, *second[1:]], "知识内容可经模型影响副作用能力。", status=Status.PROBABLE, confidence=0.9)
        for agent in [item for item in models if item.type == NodeType.AGENT.value]:
            if agent.config.get("knlToolList") and any(spec["kind"] in {"mcp", "workflow", "api_plugin", "ai_plugin"} for spec in agent.tool_specs):
                if agent.effectful or agent.high_impact:
                    self.emit("FLOW-005", [agent.id], "Agent 同时绑定知识库和副作用工具，检索内容可能影响工具选择或参数。", status=Status.PROBABLE, confidence=0.82)
                else:
                    self.emit("KB-003", [agent.id], "Agent 同时绑定知识库和只读或副作用未知的外部工具，形成待验证的指令边界。", status=Status.OBSERVED, severity=Severity.LOW)
        external_tools = [item for item in nodes if item.type == NodeType.TOOL.value and item.external]
        for tool in external_tools:
            for model in models:
                path = self.graph.path(tool.id, model.id, data_only=True)
                if path:
                    self.emit("TOOL-009", path, "外部工具输出进入模型或 Agent 上下文，形成不可信内容指令边界。", status=Status.OBSERVED, severity=Severity.LOW, confidence=0.9, missing_context=["tool_output_validation"])
                    for sink in tools:
                        second = self.graph.path(model.id, sink.id, data_only=True)
                        if second:
                            self.emit("FLOW-005", [*path, *second[1:]], "外部工具内容可经模型影响副作用能力。", status=Status.PROBABLE, confidence=0.9)
        for model in models:
            if _has_strict_structured_contract(model):
                continue
            for tool in [item for item in nodes if item.type == NodeType.TOOL.value]:
                path = self.graph.path(model.id, tool.id, data_only=True)
                if path:
                    consequential = tool.effectful or tool.high_impact
                    if _declares_free_text_output(model):
                        status = Status.CONFIRMED if consequential else Status.OBSERVED
                        severity = None if consequential else Severity.MEDIUM
                        flow_message = "模型明确声明自由文本输出进入工具参数。"
                        llm_message = "机器消费模型明确声明为自由文本，且上游没有严格结构化契约。"
                        missing_context: list[str] = []
                    else:
                        status = Status.COVERAGE_GAP
                        severity = None
                        flow_message = "模型输出进入工具参数，但 DSL 未导出可验证的严格字段 Schema，无法确认实际运行时是否受结构化响应约束。"
                        llm_message = "机器消费模型输出，但 DSL 未导出可验证的严格结构化契约。"
                        missing_context = ["model_output_schema"]
                    self.emit("FLOW-009", path, flow_message, status=status, severity=severity, missing_context=missing_context)
                    self.emit("LLM-003", path, llm_message, status=status, severity=severity, missing_context=missing_context)
        conditions = [item for item in nodes if item.type == NodeType.CONDITION.value]
        high_impact_tools = [item for item in nodes if item.type in {NodeType.TOOL.value, NodeType.CODE.value} and item.high_impact]
        for model in models:
            for condition in conditions:
                first = self.graph.path(model.id, condition.id, data_only=True)
                if not first:
                    continue
                for tool in high_impact_tools:
                    second = self.graph.path(condition.id, tool.id, control_only=True)
                    if second:
                        self.emit("LLM-006", [*first, *second[1:]], "模型输出参与通往高影响能力的分支选择；模型判断不能替代确定性授权。", status=Status.PROBABLE, confidence=0.86, missing_context=["business_authorization_policy"])
        sensitive_sources = [item for item in nodes if _sensitive(item)]
        external_sinks = [item for item in nodes if item.external]
        for source in sensitive_sources:
            for sink in external_sinks:
                path = self.graph.path(source.id, sink.id, data_only=True)
                if path:
                    self.emit("FLOW-008", path, "具有敏感语义的数据可达外部工具或输出边界。", status=Status.PROBABLE, confidence=0.78)
            for output in outputs:
                path = self.graph.path(source.id, output.id, data_only=True)
                if path and not _flatten_keys(output.config).intersection({"redaction", "masking", "audience", "accesspolicy", "access_policy"}):
                    self.emit("OUT-002", path, "敏感语义数据可达最终输出，但受众、脱敏和访问策略不在 JSON 中。", status=Status.COVERAGE_GAP, missing_context=["output_audience", "redaction_policy"])
        for kb in knowledge:
            for output in outputs:
                path = self.graph.path(kb.id, output.id, data_only=True)
                service = kb.config.get("serviceConfig") if isinstance(kb.config.get("serviceConfig"), dict) else {}
                source_disabled = service.get("whetherKnlSource") is False
                if path and _citation_required(output) and source_disabled:
                    self.emit("OUT-005", path, "知识型输出明确要求引用，但路径关闭来源传播，无法建立引用证据。", status=Status.CONFIRMED)
                elif path and source_disabled:
                    self.emit("KB-004", path, "知识来源传播已关闭；当前输出未声明引用要求，作为可追溯性加固建议。", status=Status.OBSERVED, severity=Severity.LOW, report_group="hardening")
        effectful = [item for item in nodes if item.effectful]
        for first in effectful:
            for second in effectful:
                if first.id == second.id:
                    continue
                path = self.graph.path(first.id, second.id)
                if path and not any(_flatten_keys(self.graph.nodes[item].config).intersection({"idempotency", "compensation", "circuit_breaker", "failclosed"}) for item in path if item in self.graph.nodes):
                    self.emit("FLOW-010", path, "多个副作用能力串联，路径中未发现幂等、补偿、熔断或失败关闭。", status=Status.PROBABLE, confidence=0.8)

    def _aggregate(self, findings: list[Finding]) -> list[Finding]:
        groups: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
        for item in findings:
            anchor = item.anchor_node_id or (item.node_ids[-1] if item.node_ids else "workflow")
            if item.report_group == "coverage_gap" and item.control_domain in WORKFLOW_GAP_DOMAINS:
                anchor = "workflow"
            groups[(anchor, item.control_domain, item.report_group)].append(item)
        result: list[Finding] = []
        for (anchor, domain, report_group), members in groups.items():
            strongest_status = max((item.status for item in members), key=lambda value: STATUS_RANK.get(value, -1))
            status_members = [item for item in members if item.status == strongest_status]
            primary = max(status_members, key=lambda item: (SEVERITY_RANK.get(item.severity, -1), item.confidence))
            primary.id = stable_id("RISK", anchor, domain, report_group)
            primary.status = strongest_status
            primary.severity = max((item.severity for item in status_members), key=lambda value: SEVERITY_RANK.get(value, -1))
            primary.anchor_node_id = None if anchor == "workflow" else anchor
            primary.report_group = report_group
            if anchor == "workflow":
                primary.node_ids = list(dict.fromkeys(node_id for item in members for node_id in item.node_ids))
            rule_ids = list(dict.fromkeys(rule_id for item in members for rule_id in [item.rule_id, *item.related_rule_ids]))
            primary.related_rule_ids = [item for item in rule_ids if item != primary.rule_id]
            primary.evidence_refs = list(dict.fromkeys(ref for item in members for ref in item.evidence_refs))
            primary.dsl_locations = list(dict.fromkeys(ref for item in members for ref in item.dsl_locations))
            primary.standards = list(dict.fromkeys(ref for item in members for ref in item.standards))
            primary.missing_context = list(dict.fromkeys(ref for item in members for ref in item.missing_context))
            primary.remediation = list(dict.fromkeys(ref for item in members for ref in item.remediation))
            primary.path_variants = list({tuple(item.node_ids): item.node_ids for item in members if item.node_ids}.values())
            primary.instance_summaries = [{
                "finding_id": item.id,
                "rule_id": item.rule_id,
                "status": item.status,
                "severity": item.severity,
                "path": item.node_ids,
                "message": item.message,
                "evidence_refs": item.evidence_refs,
            } for item in members]
            if len(members) > 1:
                title = self.graph.nodes[anchor].title if anchor in self.graph.nodes else "Workflow"
                primary.title = f"{title}：{domain}"
                messages = list(dict.fromkeys(item.message.rstrip("。；;，, ") for item in members))
                preview = "；".join(messages[:3])
                suffix = f"；另有 {len(messages) - 3} 类证据见实例明细" if len(messages) > 3 else ""
                primary.message = f"共 {len(members)} 个相关实例：{preview}{suffix}。"
            result.append(primary)
        return result


def execute_rules(ir: WorkflowIR, rules_path: Path) -> tuple[list[Fact], list[Finding], dict[str, Any]]:
    return SecurityEngine(ir, RuleCatalog(rules_path)).run()
