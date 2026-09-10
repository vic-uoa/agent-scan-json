from __future__ import annotations

from html import escape
import re
from typing import Any

from .models import Finding, NodeType, WorkflowIR, to_jsonable


SEVERITY_ZH = {"CRITICAL": "严重", "HIGH": "高", "MEDIUM": "中", "LOW": "低", "INFO": "提示"}
STATUS_ZH = {
    "CONFIRMED": "已确认", "OBSERVED": "已观察", "PROBABLE": "较可能",
    "CANDIDATE": "待验证", "COVERAGE_GAP": "覆盖缺口", "MITIGATED": "已缓解",
}
GATE_ZH = {"PASS": "通过", "REVIEW": "需复核", "FAIL": "不通过"}
COMPLETENESS_ZH = {"COMPLETE": "完整", "RUNTIME_EVIDENCE_REQUIRED": "需补充运行时证据", "INCOMPLETE": "扫描器覆盖不完整"}
CONTROL_DOMAIN_ZH = {
    "structure_coverage": "结构覆盖", "data_contract": "数据契约", "input_contract": "输入契约",
    "instruction_boundary": "指令与数据边界", "untrusted_content_boundary": "不可信内容边界",
    "action_authorization": "动作授权", "identity_authorization": "身份与对象授权",
    "structured_data_contract": "结构化数据契约", "execution_boundary": "执行边界",
    "egress_control": "网络出口控制", "resilience_budget": "韧性与资源预算",
    "data_protection": "数据保护", "supply_chain": "供应链", "agent_governance": "智能体治理",
    "knowledge_governance": "知识治理", "output_contract": "输出契约", "output_safety": "输出安全",
    "workflow_boundary": "子工作流边界", "tool_contract": "工具契约", "general": "通用",
}
MISSING_CONTEXT_ZH = {
    "business_authorization_policy": "业务授权策略", "callee_contract": "被调用工作流契约",
    "delegated_identity": "委派身份", "code_output_contract": "代码输出契约",
    "code_runtime_policy": "代码输入来源与运行时约束", "code_call_resolution": "动态调用语义",
    "data_classification": "数据分类", "intermediate_output_audience": "中间输出受众",
    "redaction_policy": "脱敏策略", "knowledge_acl": "知识库访问控制",
    "tenant_filter": "租户过滤", "language_specific_parser": "对应语言的静态解析器",
    "model_endpoint_allowlist": "模型端点白名单", "output_audience": "输出受众",
    "platform_branch_routing_precedence": "平台分支路由字段优先级",
    "platform_code_wrapper_semantics": "平台代码包装与执行语义", "platform_model_budget": "平台模型预算",
    "registry_signature": "注册表签名", "artifact_digest": "制品摘要",
    "renderer_sanitization": "渲染器净化策略", "runtime_action_policy": "运行时动作策略",
    "runtime_credential_injection": "运行时凭证注入方式", "runtime_egress_policy": "运行时网络出口策略",
    "runtime_fallback_policy": "运行时失败回退策略", "runtime_goal_lock": "运行时目标锁定",
    "out_of_band_kill_switch": "带外停止开关", "runtime_iam": "运行时身份与访问管理",
    "object_level_authorization": "对象级授权", "runtime_iteration_limit": "运行时迭代上限",
    "runtime_resilience_policy": "运行时韧性策略", "session_isolation": "会话隔离",
    "retention_policy": "保留期限", "history_redaction": "历史消息脱敏",
    "tool_output_validation": "工具输出验证", "tool_registry_output_schema": "工具注册表输出定义",
    "trusted_tls_terminator": "可信 TLS 终止网关", "model_egress_policy": "模型网络出口策略",
    "runtime_action_authorization": "运行时动作授权",
}


def _zh_status(value: str) -> str:
    return STATUS_ZH.get(value, value)


def _zh_gate(value: str) -> str:
    return GATE_ZH.get(value, value)


def _zh_completeness(value: str) -> str:
    return COMPLETENESS_ZH.get(value, value)


def _zh_context(values: list[str]) -> str:
    return "、".join(MISSING_CONTEXT_ZH.get(value, value) for value in values)


def _zh_title(finding: dict[str, Any]) -> str:
    title = str(finding["title"])
    domain = str(finding.get("control_domain") or "")
    return title.replace(domain, CONTROL_DOMAIN_ZH.get(domain, domain)) if domain else title


DIMENSIONS_BY_TYPE = {
    NodeType.INPUT.value: ["structure", "data_contract", "input_validation", "data_protection"],
    NodeType.OUTPUT.value: ["structure", "data_contract", "output_contract", "data_protection", "output_safety"],
    NodeType.LLM.value: ["structure", "data_contract", "instruction_boundary", "output_contract", "resilience", "data_protection"],
    NodeType.AGENT.value: ["structure", "data_contract", "instruction_boundary", "agent_governance", "tool_action", "identity_authorization", "supply_chain", "resilience", "data_protection"],
    NodeType.TOOL.value: ["structure", "data_contract", "tool_action", "identity_authorization", "network_egress", "output_contract", "supply_chain", "resilience", "data_protection"],
    NodeType.KNOWLEDGE.value: ["structure", "data_contract", "knowledge_governance", "tenant_isolation", "content_provenance", "resilience"],
    NodeType.CODE.value: ["structure", "data_contract", "code_execution", "output_contract", "sandbox", "resilience"],
    NodeType.CONDITION.value: ["structure", "data_contract", "branch_integrity", "authorization_boundary"],
    NodeType.LOOP.value: ["structure", "data_contract", "loop_termination", "resilience"],
    NodeType.STRUCTURAL.value: ["structure", "data_contract"],
    NodeType.UNKNOWN.value: ["structure", "unknown_semantics"],
}

RUNTIME_DEPENDENT_DIMENSIONS = {"identity_authorization", "tenant_isolation", "sandbox", "supply_chain", "resilience", "data_protection", "output_safety", "authorization_boundary"}


def security_coverage(ir: WorkflowIR, findings: list[Finding]) -> dict[str, Any]:
    findings_by_node: dict[str, list[Finding]] = {}
    for finding in findings:
        for node_id in finding.node_ids:
            findings_by_node.setdefault(node_id, []).append(finding)
    gaps_by_node: dict[str, list[dict[str, Any]]] = {}
    for gap in ir.coverage_gaps:
        if gap.get("node_id"):
            gaps_by_node.setdefault(str(gap["node_id"]), []).append(gap)
    reviews = []
    dimension_counts: dict[str, int] = {}
    for node in ir.nodes:
        dimensions = []
        node_findings = findings_by_node.get(node.id, [])
        for name in DIMENSIONS_BY_TYPE.get(node.type, ["structure", "unknown_semantics"]):
            matching = [item.id for item in node_findings if item.control_domain == name or name.replace("_", "") in item.control_domain.replace("_", "")]
            coverage = "STATIC_PLUS_RUNTIME" if name in RUNTIME_DEPENDENT_DIMENSIONS else "STATIC_EVIDENCE"
            dimensions.append({"name": name, "coverage": coverage, "finding_ids": matching})
            dimension_counts[coverage] = dimension_counts.get(coverage, 0) + 1
        reviews.append({
            "node_id": node.id,
            "original_type": node.original_type,
            "ir_type": node.type,
            "json_pointer": node.json_pointer,
            "container_id": node.container_id,
            "capabilities": node.capabilities,
            "dimensions": dimensions,
            "finding_ids": list(dict.fromkeys(item.id for item in node_findings)),
            "coverage_gap_reasons": sorted({str(item.get("reason")) for item in gaps_by_node.get(node.id, [])}),
        })
    unresolved_reasons = {"ambiguous_symbol", "unresolved_symbol", "required_reference_unbound", "condition_reference_unbound", "unresolved_prompt_parameter"}
    unresolved = sum(gap.get("reason") in unresolved_reasons for gap in ir.coverage_gaps)
    ref_total = len(ir.variable_refs) + unresolved
    observed_fields = int(ir.raw_metadata.get("observed_node_field_count") or 0)
    unmapped_fields = int(ir.raw_metadata.get("unmapped_node_field_count") or 0)
    return {
        "dialect_contract": ir.raw_metadata.get("dialect_contract"),
        "node_type_contract": {"supported": sum(node.type != NodeType.UNKNOWN.value for node in ir.nodes), "total": len(ir.nodes), "coverage_ratio": round(sum(node.type != NodeType.UNKNOWN.value for node in ir.nodes) / len(ir.nodes), 4) if ir.nodes else 1.0},
        "node_field_contract": {"mapped": max(0, observed_fields - unmapped_fields), "observed": observed_fields, "unmapped": unmapped_fields, "coverage_ratio": round((observed_fields - unmapped_fields) / observed_fields, 4) if observed_fields else 1.0},
        "variable_resolution": {"resolved": len(ir.variable_refs), "unresolved_or_unbound": unresolved, "total": ref_total, "coverage_ratio": round(len(ir.variable_refs) / ref_total, 4) if ref_total else 1.0},
        "review_dimension_counts": dimension_counts,
        "node_reviews": reviews,
        "interpretation": "契约覆盖率衡量已识别结构，不等于漏洞检出率；STATIC_PLUS_RUNTIME 表示已审查 DSL 证据但仍需运行环境事实。",
    }


def semantic_inventory(ir: WorkflowIR, findings: list[Finding] | None = None) -> dict[str, Any]:
    entries = [node for node in ir.nodes if node.type == NodeType.INPUT.value]
    assets = [
        {"node_id": node.id, "kind": "knowledge", "name": node.title}
        for node in ir.nodes if node.type == NodeType.KNOWLEDGE.value
    ]
    sensitive_words = ("secret", "password", "token", "credential", "customer", "phone", "身份证", "手机号", "客户", "账号", "密钥")
    for node in ir.nodes:
        semantic_parts = [node.title]
        for key in ("paramList", "params", "output", "body", "header"):
            values = node.config.get(key)
            if not isinstance(values, list):
                continue
            for item in values:
                if isinstance(item, dict):
                    semantic_parts.extend(str(item.get(field) or "") for field in ("name", "label", "description", "classification", "dataClassification"))
        if any(word in " ".join(semantic_parts).lower() for word in sensitive_words):
            assets.append({"node_id": node.id, "kind": "potential_sensitive_data", "name": node.title})
    boundaries = []
    for node in ir.nodes:
        if node.external:
            boundaries.append({"node_id": node.id, "kind": "external_capability", "capabilities": node.capabilities})
        if node.type in {NodeType.LLM.value, NodeType.AGENT.value}:
            boundaries.append({"node_id": node.id, "kind": "model_context", "capabilities": node.capabilities})
    return {
        "entry_points": [{"node_id": node.id, "name": node.title} for node in entries],
        "assets": assets,
        "trust_boundaries": boundaries,
        "capabilities": [{"node_id": node.id, "items": node.capabilities} for node in ir.nodes if node.capabilities],
        "assumptions": ["DSL 未包含的 IAM、ACL、网络策略、注册表签名和运行时沙盒保持未知。"],
        "security_coverage": security_coverage(ir, findings or []),
        "producer": "deterministic-semantic-inventory",
    }


def attack_surface(ir: WorkflowIR, findings: list[Finding], tests: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    case_by_finding: dict[str, list[str]] = {}
    for case in tests.get("cases", []):
        for finding_id in case.get("finding_ids", []):
            case_by_finding.setdefault(finding_id, []).append(case["case_id"])
    paths = []
    for finding in findings:
        if finding.report_group != "risk" or finding.status == "COVERAGE_GAP":
            continue
        variants = finding.path_variants or ([finding.node_ids] if finding.node_ids else [])
        for index, path in enumerate(variants):
            paths.append({
                "path_id": f"{finding.id}-P{index + 1}",
                "finding_id": finding.id,
                "rule_ids": [finding.rule_id, *finding.related_rule_ids],
                "nodes": path,
                "status": finding.status,
                "severity": finding.severity,
                "control_domain": finding.control_domain,
                "test_case_ids": case_by_finding.get(finding.id, []),
            })
    return {
        "entry_points": inventory["entry_points"],
        "assets": inventory["assets"],
        "trust_boundaries": inventory["trust_boundaries"],
        "capabilities": inventory["capabilities"],
        "attack_paths": paths,
        "coverage_gaps": ir.coverage_gaps,
        "security_coverage": inventory.get("security_coverage", {}),
    }


def dynamic_plan(surface: dict[str, Any], tests: dict[str, Any]) -> dict[str, Any]:
    return {
        "execution_authorized": False,
        "required_controls": [
            "deny_by_default_network", "synthetic_credentials", "read_only_fixtures",
            "blocked_real_side_effects", "cpu_memory_time_token_iteration_limits",
        ],
        "test_cases": tests.get("cases", []),
        "attack_paths": surface.get("attack_paths", []),
    }


def report_json(ir: WorkflowIR, findings: list[Finding], gate: dict[str, Any], tests: dict[str, Any], surface: dict[str, Any], model_advisory: dict[str, Any] | None = None) -> dict[str, Any]:
    grouped = {
        name: [item for item in findings if item.report_group == name]
        for name in ("risk", "posture", "hardening", "coverage_gap")
    }
    severities = {name: sum(item.severity == name for item in findings) for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    statuses = {name: sum(item.status == name for item in findings) for name in ("CONFIRMED", "OBSERVED", "PROBABLE", "CANDIDATE", "COVERAGE_GAP", "MITIGATED")}
    node_map = ir.node_map()
    workflow_nodes = []
    for node in ir.nodes:
        workflow_nodes.append({
            "id": node.id,
            "title": node.title,
            "type": node.type,
            "original_type": node.original_type,
            "container_id": node.container_id,
            "capabilities": node.capabilities,
            "position": ir.raw_metadata.get("canvas_positions", {}).get(node.id),
            **_condition_presentation(node, node_map),
        })
    return {
        "workflow": {
            "id": ir.workflow_id,
            "hash": ir.workflow_hash,
            "source_shape": ir.source_shape,
            "node_count": len(ir.nodes),
            "edge_count": len(ir.edges),
            "node_labels": {node.id: node.title for node in ir.nodes},
            "nodes": workflow_nodes,
            "edges": [to_jsonable(edge) for edge in ir.edges],
        },
        "summary": {
            "finding_count": len(grouped["risk"]),
            "risk_item_count": len(grouped["risk"]),
            "posture_observation_count": len(grouped["posture"]),
            "hardening_observation_count": len(grouped["hardening"]),
            "coverage_gap_count": len(grouped["coverage_gap"]),
            "total_record_count": len(findings),
            "severities": severities,
            "statuses": statuses,
            "quality_gate": gate["result"],
            "risk_gate": gate.get("risk_gate_result", gate["result"]),
            "completeness_result": gate.get("completeness_result", "COMPLETE"),
            "scanner_gap_count": len(gate.get("scanner_gap_ids", [])),
            "runtime_gap_count": len(gate.get("runtime_gap_ids", [])),
        },
        "findings": findings,
        "test_cluster_summary": {"case_count": len(tests.get("cases", [])), **tests.get("generation_audit", {})},
        "attack_surface": surface,
        "security_coverage": surface.get("security_coverage", {}),
        "model_advisory": model_advisory or {"enabled": False, "authoritative": False},
        "limitations": [
            "本报告仅分析导出 JSON 可见事实。",
            "未执行工作流、工具、MCP、提示词、代码或测试载荷。",
            "门禁通过不表示不存在运行时漏洞。",
        ],
    }


def _condition_presentation(node: Any, node_map: dict[str, Any]) -> dict[str, Any]:
    """Convert the internal JUDGE contract into report-friendly branch labels."""
    if getattr(node, "type", None) != NodeType.CONDITION.value:
        return {}
    cases = node.config.get("conditionList") if isinstance(node.config, dict) else None
    if not isinstance(cases, list):
        return {}
    labels: dict[str, str] = {}
    subjects: list[str] = []
    output_aliases = {
        str(candidate.config.get("outputName")): candidate.title
        for candidate in node_map.values()
        if isinstance(candidate.config, dict) and candidate.config.get("outputName")
    }
    for case_index, case in enumerate(cases):
        if not isinstance(case, dict):
            continue
        raw_handle = case.get("handleId", case_index)
        conditions = [item for item in case.get("subConditions", []) if isinstance(item, dict)]
        fragments: list[str] = []
        for condition in conditions:
            raw_subject = str(condition.get("name") or "条件值")
            subject = output_aliases.get(raw_subject, raw_subject)
            subjects.append(subject)
            operator = _condition_operator_label(condition.get("condition"))
            fragments.append(f"{subject} {operator}「{condition.get('value')}」")
        joiner = " 或 " if str(case.get("logicalOperator") or case.get("logical_operator") or "and").lower() == "or" else " 且 "
        label = joiner.join(fragments) or f"条件 {case_index + 1}"
        for key in {str(raw_handle), str(case_index), f"el-right-judge-{raw_handle}"}:
            labels[key] = label
    if labels:
        labels.setdefault("false", "否则")
    return {
        "branch_conditions": labels,
        "condition_subject": " / ".join(dict.fromkeys(subjects)) or "条件值",
        "condition_case_count": len(cases),
    }


def _condition_operator_label(operator: Any) -> str:
    return {
        "EQ": "等于", "NE": "不等于", "GT": "大于", "GTE": "大于等于",
        "LT": "小于", "LTE": "小于等于", "CONTAINS": "包含",
        "NOT_CONTAINS": "不包含", "IS_EMPTY": "为空", "IS_NOT_EMPTY": "不为空",
        "STARTS_WITH": "开头为", "ENDS_WITH": "结尾为", "IN": "属于",
        "NOT_IN": "不属于", "REGEX": "匹配",
    }.get(str(operator or "").upper(), str(operator or "满足"))


def render_html_report(report: dict[str, Any]) -> str:
    """Render one self-contained HTML report with embedded workflow diagrams."""
    summary = report.get("summary", {})
    workflow = report.get("workflow", {})
    node_by_id = {
        str(item.get("id")): item
        for item in workflow.get("nodes", [])
        if isinstance(item, dict)
    }
    findings = [item for item in report.get("findings", []) if isinstance(item, dict)]
    gate = str(summary.get("risk_gate") or summary.get("quality_gate") or "UNKNOWN")
    completeness = str(summary.get("completeness_result") or "COMPLETE")
    attack_paths = report.get("attack_surface", {}).get("attack_paths", [])
    report_title = f"{workflow.get('id', 'workflow')} · 安全扫描报告"

    def esc(value: Any) -> str:
        return escape(str(value if value not in (None, "") else "—"), quote=True)

    def severity_label(value: Any) -> str:
        return {"CRITICAL": "严重", "HIGH": "高危", "MEDIUM": "中危", "LOW": "低危", "INFO": "信息"}.get(str(value), str(value))

    def status_label(value: Any) -> str:
        return STATUS_ZH.get(str(value), str(value))

    def group_label(value: Any) -> str:
        return {"risk": "安全风险", "posture": "配置观察", "hardening": "加固建议", "coverage_gap": "覆盖缺口"}.get(str(value), str(value))

    def gate_label(value: str) -> str:
        return {"FAIL": "阻断", "REVIEW": "需复核", "PASS": "通过"}.get(value, value)

    def completeness_label(value: str) -> str:
        return COMPLETENESS_ZH.get(value, value)

    def badge(kind: str, value: Any, label: str) -> str:
        return f'<span class="badge {esc(kind)} {esc(value)}">{esc(label)}</span>'

    def node_label(node_id: Any) -> str:
        node = node_by_id.get(str(node_id), {})
        return str(node.get("title") or node_id or "工作流")

    risk_findings = [item for item in findings if item.get("report_group", "risk") == "risk" and item.get("status") != "MITIGATED"]
    severity_counts = {
        level: sum(item.get("severity") == level for item in risk_findings)
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    }
    highest_severity = max(
        (level for level, count in severity_counts.items() if count),
        key=_severity_rank,
        default=None,
    )
    highest_risk_html = (
        badge("severity", highest_severity, severity_label(highest_severity))
        if highest_severity else '<span class="no-risk">未形成风险项</span>'
    )
    metrics = [
        ("安全风险", summary.get("risk_item_count", 0)),
        ("已确认", summary.get("statuses", {}).get("CONFIRMED", 0)),
        ("覆盖缺口", summary.get("coverage_gap_count", 0)),
        ("工作流", f"{workflow.get('node_count', 0)} 节点 · {workflow.get('edge_count', 0)} 连线"),
    ]
    metrics_html = "".join(
        f'<div class="metric"><span>{esc(label)}</span><strong>{esc(value)}</strong></div>'
        for label, value in metrics
    )
    severity_chips = "".join(
        f'<span class="count-chip {esc(level)}">{esc(severity_label(level))} {count}</span>'
        for level, count in severity_counts.items() if count
    ) or '<span class="muted">未形成安全风险项</span>'

    finding_rows: list[str] = []
    for finding_index, finding in enumerate(findings):
        severity = str(finding.get("severity") or "INFO")
        status = str(finding.get("status") or "UNKNOWN")
        group = str(finding.get("report_group") or "risk")
        node_ids = [str(value) for value in finding.get("node_ids", [])]
        path_copy = " → ".join(node_label(node_id) for node_id in node_ids) or "工作流级"
        rules = "、".join(dict.fromkeys(filter(None, [str(finding.get("rule_id") or ""), *map(str, finding.get("related_rule_ids", []))])))
        confidence = float(finding.get("confidence") or 0)
        remediations = finding.get("remediation") or ["人工复核并补充匹配控制。"]
        remediation_html = "".join(f"<li>{esc(item)}</li>" for item in remediations)
        missing_context = "；".join(MISSING_CONTEXT_ZH.get(str(value), str(value)) for value in finding.get("missing_context", [])) or "—"
        validation = str(finding.get("dynamic_test") or "—")

        related_paths = []
        for path_item in attack_paths:
            if str(path_item.get("finding_id")) != str(finding.get("id")):
                continue
            path = path_item.get("nodes") or path_item.get("path") or []
            if path:
                related_paths.append([str(value) for value in path])
        if group == "risk" and not related_paths:
            related_paths = [
                [str(value) for value in path]
                for path in (finding.get("path_variants") or ([node_ids] if node_ids else []))
                if path
            ]
        related_paths = list({tuple(path): path for path in related_paths}.values())
        chains: list[str] = []
        for chain_index, path in enumerate(related_paths):
            chain_copy = " → ".join(node_label(node_id) for node_id in path)
            svg_id = f"finding-{finding_index}-{chain_index}"
            open_attribute = " open" if len(related_paths) == 1 else ""
            chains.append(
                f'<details class="bound-chain"{open_attribute}><summary class="bound-chain-head">'
                f'<div><h4>对应逻辑链</h4><p>{esc(chain_copy)}</p></div><span>{len(path)} 个节点 · 展开</span>'
                f'</summary><div class="bound-chain-frame">{render_risk_chain_svg(workflow, path, svg_id, severity)}</div>'
                f'<div class="bound-chain-meta"><span><b>规则</b>{esc(rules)}</span></div></details>'
            )
        chains_html = "".join(chains)
        if group == "risk" and not chains_html:
            chains_html = '<div class="bound-chain-empty"><strong>该风险没有可展示的完整节点路径</strong></div>'

        finding_rows.append(
            f'<details class="finding issue-item" data-severity="{esc(severity)}" data-status="{esc(status)}" data-group="{esc(group)}">'
            '<summary><span class="disclosure" aria-hidden="true">›</span><div class="finding-heading">'
            f'<div class="badge-row">{badge("group", group, group_label(group))}{badge("severity", severity, severity_label(severity))}{badge("status", status, status_label(status))}</div>'
            f'<div class="finding-title">{esc(_zh_title(finding))}</div><div class="finding-path">{esc(path_copy)}</div></div>'
            f'<span class="finding-side">{len(related_paths)} 条逻辑链</span></summary>'
            '<div class="finding-body"><div class="evidence-panel"><h4>判定依据</h4>'
            f'<p>{esc(finding.get("message"))}</p></div><div class="remediation-panel"><h4>修复建议</h4><ul>{remediation_html}</ul></div>'
            '<details class="technical"><summary>技术证据</summary><dl>'
            f'<dt>风险编号</dt><dd>{esc(finding.get("id"))}</dd><dt>责任节点</dt><dd>{esc(node_label(finding.get("anchor_node_id")))}</dd>'
            f'<dt>规则映射</dt><dd>{esc(rules)}</dd><dt>控制域</dt><dd>{esc(CONTROL_DOMAIN_ZH.get(str(finding.get("control_domain")), finding.get("control_domain")))}</dd>'
            f'<dt>证据状态</dt><dd>{esc(status)} · 置信度 {confidence:.2f}</dd><dt>后续验证</dt><dd>{esc(validation)}</dd>'
            f'<dt>待核实信息</dt><dd>{esc(missing_context)}</dd><dt>DSL 位置</dt><dd>{esc("； ".join(map(str, finding.get("dsl_locations", []))) or "未记录")}</dd>'
            f'</dl></details>{chains_html}</div></details>'
        )
    findings_html = "".join(finding_rows) or '<div class="empty">未发现需要展示的扫描记录。</div>'
    workflow_svg = render_workflow_svg(workflow, [], "workflow")
    gate_copy = {
        "FAIL": "存在已确认的高危或严重风险，建议阻断发布。",
        "REVIEW": "存在需要进一步处理或人工复核的静态证据。",
        "PASS": "当前静态证据未触发发布阻断或人工复核。",
    }.get(gate, "请结合风险详情人工判断。")
    limitations = "".join(f"<li>{esc(item)}</li>" for item in report.get("limitations", []))

    style = """
:root{color-scheme:light;--ink:#162033;--muted:#586779;--canvas:#f4f7fa;--line:#d5dee9;--surface:#fff;--navy:#142033;--focus:#2563eb}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--canvas);color:var(--ink);font:15px/1.6 Inter,"Microsoft YaHei",system-ui,sans-serif}
a{color:inherit}button,select{font:inherit}header{background:var(--navy);color:#fff;padding:28px max(24px,calc((100vw - 1220px)/2)) 62px}header h1{margin:0;font-size:28px;letter-spacing:-.02em;text-wrap:balance}header p{margin:4px 0 0;color:#d5deea;font-size:13px}
main{max-width:1220px;margin:-38px auto 0;padding:0 22px 32px}.summary-shell{display:grid;grid-template-columns:310px 1fr;background:#fff;border:1px solid #cbd5e1;border-radius:16px;overflow:hidden}.decision{padding:20px 24px;background:#f8fafc;border-right:1px solid var(--line)}.decision>small{display:block;color:var(--muted);font-weight:700}.decision>strong{display:block;margin:4px 0;font-size:28px}.decision.REVIEW>strong{color:#8a5b00}.decision.FAIL>strong{color:#a92318}.decision.PASS>strong{color:#126f37}.decision p{margin:4px 0 0;color:#44546a;font-size:13px}.decision-meta{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:13px;padding-top:11px;border-top:1px solid var(--line);font-size:12px}.decision-meta span:first-child{color:#475569}.no-risk{color:#126f37;font-weight:800}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));align-items:center}.metric{padding:20px;border-right:1px solid #e8edf3}.metric:last-child{border:0}.metric span{display:block;color:var(--muted);font-size:12px}.metric strong{display:block;margin-top:4px;font-size:19px;line-height:1.3}
.jump-nav{display:flex;gap:8px;margin:16px 0 2px;overflow:auto}.jump-nav a{text-decoration:none;background:#fff;border:1px solid var(--line);border-radius:999px;padding:7px 13px;color:#44546a;font-size:13px;white-space:nowrap}.jump-nav a:hover{border-color:#8798ac;color:#0f172a}.jump-nav a:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid rgba(37,99,235,.3);outline-offset:2px}
.report-section{padding:30px 0;border-bottom:1px solid var(--line);scroll-margin-top:12px}.section-head{display:flex;justify-content:space-between;align-items:end;gap:18px;margin-bottom:16px}.section-head h2{margin:0;font-size:22px;letter-spacing:-.015em;text-wrap:balance}.section-head p{max-width:720px;margin:4px 0 0;color:var(--muted);text-wrap:pretty}.count-row,.badge-row{display:flex;gap:7px;flex-wrap:wrap}.badge,.count-chip{display:inline-flex;align-items:center;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:800;white-space:nowrap}.severity.CRITICAL,.count-chip.CRITICAL{background:#fee2e2;color:#8f1717}.severity.HIGH,.count-chip.HIGH{background:#ffedd5;color:#8a2e0e}.severity.MEDIUM,.count-chip.MEDIUM{background:#fef3c7;color:#744b08}.severity.LOW,.count-chip.LOW{background:#e0f2fe;color:#075985}.severity.INFO,.count-chip.INFO{background:#dcfce7;color:#166534}.status{background:#edf2f7;color:#3e4c5f}.status.CONFIRMED{background:#fee2e2;color:#8f1717}.status.PROBABLE{background:#fff2bd;color:#6c4900}.status.OBSERVED{background:#e0f2fe;color:#075985}.status.CANDIDATE,.status.COVERAGE_GAP{background:#eef2f6;color:#3e4c5f}.group{background:#e9eef5;color:#334155}.group.risk{background:#e9e5ff;color:#49349a}
.diagram-frame{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:12px}.workflow-svg{display:block;min-width:780px;width:100%;height:auto}.diagram-note{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:10px;color:var(--muted);font-size:12px}.legend{display:flex;flex-wrap:wrap;gap:12px}.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;vertical-align:-1px}
.filters{display:flex;gap:10px;flex-wrap:wrap}.filters label{display:grid;gap:4px;color:var(--muted);font-size:12px}.filters select{height:36px;min-width:132px;border:1px solid #b9c5d3;border-radius:8px;padding:0 9px;background:#fff;color:var(--ink)}#findings{display:grid;gap:10px}.finding{background:#fff;border:1px solid var(--line);border-radius:12px;overflow:hidden}.finding>summary{cursor:pointer;list-style:none;padding:15px 17px;display:grid;grid-template-columns:18px minmax(0,1fr) auto;gap:12px;align-items:center}.finding>summary::-webkit-details-marker,.technical>summary::-webkit-details-marker,.bound-chain>summary::-webkit-details-marker{display:none}.disclosure{font-size:24px;color:#8291a4;transition:transform .18s ease-out}.finding[open] .disclosure{transform:rotate(90deg)}.finding-heading{display:grid;grid-template-columns:auto 1fr;gap:5px 12px;align-items:center}.finding-heading .badge-row{grid-row:1/3}.finding-title{font-weight:800}.finding-path{color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.finding-side{color:#586779;font-size:11px}.finding-body{display:grid;grid-template-columns:1.2fr 1fr;gap:14px;padding:0 17px 17px 47px;border-top:1px solid #e8edf3}.finding-body h4{margin:14px 0 6px}.finding-body p,.finding-body ul{margin:0}.finding-body ul{padding-left:20px}.technical{grid-column:1/-1;border-top:1px dashed var(--line);padding-top:10px}.technical>summary{cursor:pointer;color:#44546a;font-size:13px}.technical dl{display:grid;grid-template-columns:84px 1fr;gap:5px 10px;margin:10px 0 0;font-size:12px}.technical dt{color:var(--muted)}.technical dd{margin:0;word-break:break-word}.bound-chain{grid-column:1/-1;margin-top:2px;padding-top:14px;border-top:1px solid var(--line)}.bound-chain-head{display:flex;justify-content:space-between;gap:12px;align-items:end;margin-bottom:10px;cursor:pointer;list-style:none}.bound-chain-head h4{margin:0}.bound-chain-head p{margin-top:2px;color:#44546a;font-size:12px}.bound-chain-head>span{color:var(--muted);font-size:11px}.bound-chain-frame{overflow:auto;background:#f8fafc;border-radius:8px}.bound-chain-frame .workflow-svg{min-width:720px}.bound-chain-meta{display:flex;flex-wrap:wrap;gap:8px 20px;margin-top:8px;color:#586779;font-size:11px}.bound-chain-meta b{margin-right:5px;color:#334155}.bound-chain-empty{grid-column:1/-1;padding-top:12px;border-top:1px solid var(--line);color:#586779;font-size:12px}.empty{padding:26px;text-align:center;color:var(--muted)}.boundary-copy{max-width:75ch}.boundary-copy ul{padding-left:20px}footer{padding:18px 0;color:var(--muted);font-size:12px}
@media(max-width:880px){header{padding:26px 18px 58px}main{padding:0 12px 24px}.summary-shell{grid-template-columns:1fr}.decision{border-right:0;border-bottom:1px solid var(--line)}.metrics{grid-template-columns:1fr 1fr}.metric:nth-child(2){border-right:0}.metric:nth-child(-n+2){border-bottom:1px solid #e8edf3}.finding-body{grid-template-columns:1fr;padding-left:17px}.technical{grid-column:auto}.finding-heading{display:block}.finding-path{margin-top:5px}.section-head{display:block}.filters{margin-top:12px}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}.disclosure{transition:none}}
@media print{body{background:#fff}header{padding:18px 20px 48px}main{max-width:none}.jump-nav,.filters{display:none}.report-section{break-inside:avoid}.diagram-frame{border-color:#94a3b8}details:not([open])>:not(summary){display:block!important}}
"""
    script = """
const sf=document.getElementById('severityFilter'),st=document.getElementById('statusFilter'),gf=document.getElementById('groupFilter');
function filterFindings(){document.querySelectorAll('.issue-item').forEach(x=>{x.hidden=!!((sf.value&&x.dataset.severity!==sf.value)||(st.value&&x.dataset.status!==st.value)||(gf.value&&x.dataset.group!==gf.value))})}
[sf,st,gf].forEach(x=>x.addEventListener('change',filterFindings));
"""
    return f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(report_title)}</title><style>{style}</style></head>
<body><header><h1>{esc(report_title)}</h1><p>确定性静态规则扫描 · 自包含离线报告</p></header><main>
<section class="summary-shell" id="overview"><div class="decision {esc(gate)}"><small>发布门禁</small><strong>{esc(gate_label(gate))}</strong><p>{esc(gate_copy)}</p><div class="decision-meta"><span>最高风险程度</span>{highest_risk_html}</div><div class="decision-meta"><span>扫描完整性</span><strong>{esc(completeness_label(completeness))}</strong></div></div><div class="metrics">{metrics_html}</div></section>
<nav class="jump-nav" aria-label="报告导航"><a href="#overview">概览</a><a href="#workflow">工作流图</a><a href="#findings-section">风险与逻辑链</a><a href="#boundaries">扫描边界</a></nav>
<section class="report-section" id="workflow"><div class="section-head"><div><h2>工作流图</h2><p>由原始 JSON DSL 转换；有画布坐标时保留布局，否则按拓扑自动分层。</p></div><div class="count-row">{severity_chips}</div></div><div class="diagram-frame">{workflow_svg}</div><div class="diagram-note"><span class="legend"><span><i style="background:#dbeafe"></i>输入/知识</span><span><i style="background:#ede9fe"></i>模型/处理</span><span><i style="background:#fef3c7"></i>条件/循环</span><span><i style="background:#dcfce7"></i>输出/工具</span></span><span>节点标题来自 DSL，技术 ID 仅在证据区保留</span></div></section>
<section class="report-section" id="findings-section"><div class="section-head"><div><h2>风险与逻辑链</h2><p>严重度表示潜在影响，证据状态表示静态确定性；风险路径以聚焦流程图就地展示。</p></div><div class="filters"><label>类别<select id="groupFilter"><option value="">全部</option><option value="risk">安全风险</option><option value="posture">配置观察</option><option value="hardening">加固建议</option><option value="coverage_gap">覆盖缺口</option></select></label><label>严重度<select id="severityFilter"><option value="">全部</option><option value="CRITICAL">严重</option><option value="HIGH">高危</option><option value="MEDIUM">中危</option><option value="LOW">低危</option><option value="INFO">信息</option></select></label><label>证据状态<select id="statusFilter"><option value="">全部</option><option value="CONFIRMED">已确认</option><option value="OBSERVED">已观察</option><option value="PROBABLE">较可能</option><option value="CANDIDATE">待验证</option><option value="COVERAGE_GAP">覆盖缺口</option><option value="MITIGATED">已缓解</option></select></label></div></div><div id="findings">{findings_html}</div></section>
<section class="report-section boundary-copy" id="boundaries"><div class="section-head"><div><h2>扫描边界</h2><p>报告只基于 DSL 可见事实，不把未知的运行时控制包装成已确认漏洞。</p></div></div><ul>{limitations}</ul></section>
<footer>Agent JSON Workflow 静态安全扫描</footer></main><script>{script}</script></body></html>'''


def render_workflow_svg(workflow: dict[str, Any], highlight_path: list[str], svg_id: str) -> str:
    nodes = [item for item in workflow.get("nodes", []) if isinstance(item, dict)]
    edges = [item for item in workflow.get("edges", []) if isinstance(item, dict)]
    node_by_id = {str(item.get("id")): item for item in nodes}
    positions, width, height, layout_source = _workflow_positions(nodes, edges)
    node_w, node_h = 176, 72
    marker = f"arrow-{_safe_svg_id(svg_id)}"
    highlighted = set(map(str, highlight_path))
    outgoing: dict[str, list[dict[str, Any]]] = {}
    incoming: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        source, target = str(edge.get("source")), str(edge.get("target"))
        if source in positions and target in positions:
            outgoing.setdefault(source, []).append(edge)
            incoming.setdefault(target, []).append(edge)
    for source, items in outgoing.items():
        items.sort(key=lambda item: positions[str(item.get("target"))][1])
    for target, items in incoming.items():
        items.sort(key=lambda item: positions[str(item.get("source"))][1])
    edge_svg: list[str] = []
    for edge in edges:
        source, target = str(edge.get("source")), str(edge.get("target"))
        if source not in positions or target not in positions:
            continue
        x1, y1 = positions[source]; x2, y2 = positions[target]
        source_items = outgoing.get(source, [edge]); target_items = incoming.get(target, [edge])
        source_index = source_items.index(edge); target_index = target_items.index(edge)
        sy = y1 + node_h * (source_index + 1) / (len(source_items) + 1)
        ty = y2 + node_h * (target_index + 1) / (len(target_items) + 1)
        sx, tx = x1 + node_w, x2
        if tx > sx + 26:
            control = max(12, min(96, (tx - sx) * .42))
            path_d = f"M {sx:.1f} {sy:.1f} C {sx + control:.1f} {sy:.1f}, {tx - control:.1f} {ty:.1f}, {tx:.1f} {ty:.1f}"
        else:
            lane_y = max(y1 + node_h, y2 + node_h) + 26 + 10 * source_index
            path_d = f"M {sx:.1f} {sy:.1f} H {sx + 24:.1f} V {lane_y:.1f} H {tx - 24:.1f} V {ty:.1f} H {tx:.1f}"
        is_highlighted = source in highlighted and target in highlighted
        stroke = "#b91c1c" if is_highlighted else "#8fa1b5"
        edge_svg.append(f'<path d="{path_d}" fill="none" stroke="{stroke}" stroke-width="{2.4 if is_highlighted else 1.6}" marker-end="url(#{marker})"><title>{escape(node_label_for_svg(node_by_id, source))} → {escape(node_label_for_svg(node_by_id, target))}</title></path>')
        if len(source_items) > 1:
            branch_key = _edge_branch_key(edge, source_index)
            full_label = _branch_label(branch_key, source_index, node_by_id.get(source))
            short_label = _compact_branch_label(branch_key, source_index, node_by_id.get(source))
            label_x, label_y = sx + 12, sy - 7
            label_w = max(36, 9 * len(short_label) + 12)
            edge_svg.append(f'<g><title>{escape(full_label)}</title><rect x="{label_x:.1f}" y="{label_y - 11:.1f}" width="{label_w}" height="17" rx="7" fill="#fff" stroke="#dbe3ee"/><text x="{label_x + 6:.1f}" y="{label_y + 1:.1f}" font-size="9" fill="#53657a">{escape(short_label)}</text></g>')
    node_svg: list[str] = []
    for node_id, node in node_by_id.items():
        x, y = positions[node_id]
        node_type = str(node.get("type") or "UNKNOWN")
        stroke = "#b91c1c" if node_id in highlighted else "#b9c6d5"
        stroke_width = 2 if node_id in highlighted else 1
        node_svg.append(
            f'<g><rect x="{x}" y="{y}" width="{node_w}" height="{node_h}" rx="9" fill="{_node_fill(node_type)}" stroke="{stroke}" stroke-width="{stroke_width}"/>'
            f'<text x="{x + 11}" y="{y + 25}" font-size="12" font-weight="700" fill="#172033">{escape(_svg_text(node.get("title") or node_id, 19))}</text>'
            f'<text x="{x + 11}" y="{y + 51}" font-size="10" fill="#475569">{escape(_svg_text(_condition_type_copy(node, node_type), 24))}</text></g>'
        )
    return f'<svg class="workflow-svg" data-layout="{layout_source}" viewBox="0 0 {width} {height}" role="img" aria-label="工作流流程图"><defs><marker id="{marker}" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="#8fa1b5"/></marker></defs>{"".join(edge_svg)}{"".join(node_svg)}</svg>'


def render_risk_chain_svg(workflow: dict[str, Any], path: list[str], svg_id: str, severity: str) -> str:
    nodes = {str(item.get("id")): item for item in workflow.get("nodes", []) if isinstance(item, dict)}
    edges = [item for item in workflow.get("edges", []) if isinstance(item, dict)]
    visible = [node_id for node_id in path if node_id in nodes]
    width = max(760, 74 + 226 * len(visible))
    height = 164
    node_w, node_h, node_y = 176, 74, 44
    color = _risk_color(severity)
    marker = f"focus-arrow-{_safe_svg_id(svg_id)}"
    body: list[str] = []
    for index in range(len(visible) - 1):
        source, target = visible[index], visible[index + 1]
        sx = 42 + index * 226 + node_w; tx = 42 + (index + 1) * 226; cy = node_y + node_h / 2
        edge = next((item for item in edges if str(item.get("source")) == source and str(item.get("target")) == target), {})
        branch_key = _edge_branch_key(edge, index)
        label = _branch_label(branch_key, index, nodes.get(source)) if edge else ""
        short_label = _compact_branch_label(branch_key, index, nodes.get(source)) if label else ""
        body.append(f'<path d="M {sx} {cy:.1f} H {tx}" fill="none" stroke="{color}" stroke-width="2.4" marker-end="url(#{marker})"/>')
        if short_label:
            mid = (sx + tx) / 2
            body.append(f'<text x="{mid:.1f}" y="{cy - 9:.1f}" text-anchor="middle" font-size="9" font-weight="700" fill="{color}"><title>{escape(label)}</title>{escape(short_label)}</text>')
    for index, node_id in enumerate(visible):
        node = nodes[node_id]; x = 42 + index * 226
        body.append(
            f'<g><rect x="{x}" y="{node_y}" width="{node_w}" height="{node_h}" rx="9" fill="{_node_fill(str(node.get("type") or "UNKNOWN"))}" stroke="{color}" stroke-width="1.7"/>'
            f'<circle cx="{x + 15}" cy="{node_y + 15}" r="10" fill="{color}"/><text x="{x + 15}" y="{node_y + 18.5}" text-anchor="middle" font-size="9" font-weight="800" fill="#fff">{index + 1}</text>'
            f'<text x="{x + 31}" y="{node_y + 20}" font-size="11.5" font-weight="700" fill="#172033">{escape(_svg_text(node.get("title") or node_id, 19))}</text>'
            f'<text x="{x + 12}" y="{node_y + 53}" font-size="10" fill="#53657a">{escape(_svg_text(_condition_type_copy(node, str(node.get("type") or "UNKNOWN")), 23))}</text></g>'
        )
    if not visible:
        body.append('<text x="28" y="55" font-size="13" fill="#64748b">该风险没有可展示的节点路径。</text>')
    return f'<svg class="workflow-svg" viewBox="0 0 {width} {height}" role="img" aria-label="风险逻辑链"><defs><marker id="{marker}" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="{color}"/></marker></defs>{"".join(body)}</svg>'


def _workflow_positions(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> tuple[dict[str, tuple[int, int]], int, int, str]:
    canvas: dict[str, tuple[float, float]] = {}
    for node in nodes:
        position = node.get("position")
        if not isinstance(position, dict):
            continue
        try:
            canvas[str(node.get("id"))] = (float(position["x"]), float(position["y"]))
        except (KeyError, TypeError, ValueError):
            continue
    positions: dict[str, tuple[int, int]] = {}
    if canvas:
        min_x = min(value[0] for value in canvas.values()); min_y = min(value[1] for value in canvas.values())
        x_clusters: list[list[float]] = []
        for x in sorted({value[0] for value in canvas.values()}):
            if x_clusters and x - x_clusters[-1][-1] <= 80:
                x_clusters[-1].append(x)
            else:
                x_clusters.append([x])
        normalized_x: dict[float, int] = {}
        previous_column: int | None = None
        for cluster in x_clusters:
            desired = 44 + int(((sum(cluster) / len(cluster)) - min_x) * .72)
            assigned = desired if previous_column is None else max(desired, previous_column + 300)
            for raw_x in cluster:
                normalized_x[raw_x] = assigned
            previous_column = assigned
        by_column: dict[int, list[tuple[str, float]]] = {}
        for node_id, (x, y) in canvas.items():
            by_column.setdefault(normalized_x[x], []).append((node_id, y))
        for column_x, column_nodes in by_column.items():
            previous_y: int | None = None
            for node_id, raw_y in sorted(column_nodes, key=lambda item: item[1]):
                desired_y = 38 + int((raw_y - min_y) * .72)
                assigned_y = desired_y if previous_y is None else max(desired_y, previous_y + 92)
                positions[node_id] = (column_x, assigned_y); previous_y = assigned_y
        bottom = max(y for _, y in positions.values()) + 112
        for index, node in enumerate(item for item in nodes if str(item.get("id")) not in positions):
            positions[str(node.get("id"))] = (44, bottom + index * 104)
        return positions, max(800, max(x for x, _ in positions.values()) + 224), max(230, max(y for _, y in positions.values()) + 122), "dsl-canvas"

    node_ids = [str(item.get("id")) for item in nodes]
    incoming = {node_id: 0 for node_id in node_ids}; outgoing = {node_id: [] for node_id in node_ids}
    for edge in edges:
        source, target = str(edge.get("source")), str(edge.get("target"))
        if source in outgoing and target in incoming:
            outgoing[source].append(target); incoming[target] += 1
    queue = sorted(node_id for node_id, count in incoming.items() if count == 0)
    ranks = {node_id: 0 for node_id in queue}
    while queue:
        current = queue.pop(0)
        for target in sorted(outgoing[current]):
            ranks[target] = max(ranks.get(target, 0), ranks[current] + 1)
            incoming[target] -= 1
            if incoming[target] == 0:
                queue.append(target)
    for node_id in node_ids:
        ranks.setdefault(node_id, max(ranks.values(), default=-1) + 1)
    columns: dict[int, list[str]] = {}
    for node_id, rank in ranks.items():
        columns.setdefault(rank, []).append(node_id)
    for rank in sorted(columns):
        for index, node_id in enumerate(sorted(columns[rank])):
            positions[node_id] = (44 + rank * 244, 38 + index * 106)
    return positions, max(800, max((x for x, _ in positions.values()), default=0) + 224), max(230, max((y for _, y in positions.values()), default=0) + 122), "derived-layered"


def _edge_branch_key(edge: dict[str, Any], fallback_index: int) -> Any:
    for key in ("source_handle", "sourceHandle", "source_index", "sourceIndex"):
        if edge.get(key) not in (None, ""):
            return edge[key]
    return fallback_index


def _branch_label(handle: Any, index: int, source_node: dict[str, Any] | None = None) -> str:
    value = str(handle if handle is not None else "")
    labels = source_node.get("branch_conditions", {}) if isinstance(source_node, dict) else {}
    if isinstance(labels, dict) and value in labels:
        return str(labels[value])
    if value == "true":
        return "是 / true"
    if value == "false":
        return "否则"
    return f"分支 {index + 1}"


def _compact_branch_label(handle: Any, index: int, source_node: dict[str, Any] | None = None) -> str:
    value = str(handle if handle is not None else "")
    labels = source_node.get("branch_conditions", {}) if isinstance(source_node, dict) else {}
    if isinstance(labels, dict) and value in labels:
        return "否则" if value == "false" or str(labels[value]) == "否则" else f"条件 {index + 1}"
    if value == "true":
        return "是"
    if value == "false":
        return "否则"
    return f"分支 {index + 1}"


def _condition_type_copy(node: dict[str, Any], fallback: str) -> str:
    if fallback != NodeType.CONDITION.value:
        return fallback
    return f"条件 · {node.get('condition_subject') or '条件值'} · {int(node.get('condition_case_count') or 0)} 个分支"


def node_label_for_svg(nodes: dict[str, dict[str, Any]], node_id: str) -> str:
    return str(nodes.get(node_id, {}).get("title") or node_id)


def _risk_color(severity: str) -> str:
    return {"CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#a86508", "LOW": "#0276a8"}.get(severity, "#64748b")


def _node_fill(node_type: str) -> str:
    if node_type in {NodeType.INPUT.value, NodeType.KNOWLEDGE.value}:
        return "#dbeafe"
    if node_type in {NodeType.CONDITION.value, NodeType.LOOP.value, NodeType.STRUCTURAL.value}:
        return "#fef3c7"
    if node_type in {NodeType.TOOL.value, NodeType.OUTPUT.value}:
        return "#dcfce7"
    return "#ede9fe"


def _svg_text(value: Any, limit: int) -> str:
    text = str(value if value is not None else "")
    return text if len(text) <= limit else f"{text[:max(1, limit - 1)]}…"


def _severity_rank(value: Any) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(str(value), -1)


def _safe_svg_id(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]", "-", str(value)) or "diagram"
