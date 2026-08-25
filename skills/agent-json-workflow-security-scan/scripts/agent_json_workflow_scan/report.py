from __future__ import annotations

from typing import Any

from .models import Finding, NodeType, WorkflowIR


SEVERITY_ZH = {"CRITICAL": "严重", "HIGH": "高", "MEDIUM": "中", "LOW": "低", "INFO": "提示"}
STATUS_ZH = {
    "CONFIRMED": "已确认", "OBSERVED": "已观察", "PROBABLE": "较可能",
    "CANDIDATE": "待验证", "COVERAGE_GAP": "覆盖缺口", "MITIGATED": "已缓解",
}
GATE_ZH = {"PASS": "通过", "REVIEW": "需复核", "FAIL": "不通过"}
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
    assets.extend(
        {"node_id": node.id, "kind": "potential_sensitive_data", "name": node.title}
        for node in ir.nodes if any(word in str(node.config).lower() for word in ("secret", "token", "password", "customer", "phone", "客户", "账号", "密钥"))
    )
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
    return {
        "workflow": {"id": ir.workflow_id, "hash": ir.workflow_hash, "source_shape": ir.source_shape, "node_count": len(ir.nodes), "edge_count": len(ir.edges)},
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


def report_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# 智能体 JSON 工作流静态安全扫描报告", "",
        f"- 工作流：`{report['workflow']['id']}`",
        f"- 发布门禁：**{_zh_gate(summary['quality_gate'])}**",
        f"- 安全风险项：{summary['risk_item_count']}",
        f"- JSON 原生配置观察：{summary['posture_observation_count']}",
        f"- 加固建议：{summary['hardening_observation_count']}",
        f"- 覆盖缺口：{summary['coverage_gap_count']}",
        f"- 全部记录：{summary['total_record_count']}",
        f"- 节点数 / 边数：{report['workflow']['node_count']} / {report['workflow']['edge_count']}",
        "", "## 扫描覆盖情况", "",
    ]
    coverage = report.get("security_coverage", {})
    node_contract = coverage.get("node_type_contract", {})
    field_contract = coverage.get("node_field_contract", {})
    variable_resolution = coverage.get("variable_resolution", {})
    lines.extend([
        f"- 节点类型契约覆盖：{node_contract.get('supported', 0)}/{node_contract.get('total', 0)}（{node_contract.get('coverage_ratio', 0):.1%}）",
        f"- 节点字段契约覆盖：{field_contract.get('mapped', 0)}/{field_contract.get('observed', 0)}（{field_contract.get('coverage_ratio', 0):.1%}）",
        f"- 变量引用解析：{variable_resolution.get('resolved', 0)}/{variable_resolution.get('total', 0)}（{variable_resolution.get('coverage_ratio', 0):.1%}）",
        "- 上述指标衡量解析器和字段契约覆盖程度，不代表漏洞检出准确率。",
        "- 只有安全风险项参与发布门禁；配置观察、加固建议和覆盖缺口分别统计。",
    ])

    def add_group(title: str, group: str, empty: str) -> None:
        lines.extend(["", f"## {title}", ""])
        members = [item for item in report["findings"] if item.get("report_group", "risk") == group]
        if not members:
            lines.append(empty)
            return
        for finding in members:
            lines.extend([
                f"### [{SEVERITY_ZH.get(finding['severity'], finding['severity'])}] {_zh_title(finding)}", "",
                f"- 证据状态：{_zh_status(finding['status'])}",
                f"- 规则：`{finding['rule_id']}`" + (f"；关联规则：`{', '.join(finding.get('related_rule_ids', []))}`" if finding.get("related_rule_ids") else ""),
                f"- 控制域：{CONTROL_DOMAIN_ZH.get(finding['control_domain'], finding['control_domain'])}",
                f"- 关联节点：`{', '.join(finding.get('node_ids', [])) or '工作流'}`",
                f"- 证据说明：{finding['message']}",
            ])
            if finding.get("missing_context"):
                lines.append(f"- 尚缺上下文：{_zh_context(finding['missing_context'])}")
            lines.append(f"- 修复建议：{' '.join(finding.get('remediation', []))}")
            lines.append("")

    add_group("安全风险项", "risk", "未发现当前规则和 JSON 可见范围内的安全风险项。")
    add_group("JSON 原生配置观察", "posture", "没有额外的 JSON 原生配置观察。")
    add_group("加固建议", "hardening", "没有额外的加固建议。")
    add_group("覆盖缺口", "coverage_gap", "没有记录额外覆盖缺口。")
    advisory = report.get("model_advisory", {})
    lines.extend(["## 模型辅助说明", ""])
    if advisory.get("enabled"):
        lines.append("模型建议已启用，但不参与 Finding、状态、严重度、置信度或质量门禁。")
        if advisory.get("executive_summary"):
            lines.append(f"非权威摘要：{advisory['executive_summary']}")
        lines.append(f"接受的附加测试：{len(advisory.get('accepted_case_ids', []))}；拒绝的建议：{len(advisory.get('rejected', []))}。")
    else:
        lines.append("未启用模型建议；全部结论和门禁来自确定性解析与规则。")
    lines.append("")
    lines.extend(["## 使用边界", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def attack_surface_markdown(surface: dict[str, Any]) -> str:
    lines = ["# 工作流攻击面", "", "## 入口", ""]
    lines.extend(f"- `{item['node_id']}` — {item['name']}" for item in surface.get("entry_points", []))
    lines.extend(["", "## 信任边界", ""])
    boundary_zh = {"model_context": "模型上下文边界", "external_capability": "外部能力边界"}
    lines.extend(f"- `{item['node_id']}` — {boundary_zh.get(item['kind'], item['kind'])}" for item in surface.get("trust_boundaries", []))
    lines.extend(["", "## 攻击路径", "", "| 严重等级 | 证据状态 | 控制域 | 路径 |", "|---|---|---|---|"])
    for item in surface.get("attack_paths", []):
        lines.append(f"| {SEVERITY_ZH.get(item['severity'], item['severity'])} | {STATUS_ZH.get(item['status'], item['status'])} | {CONTROL_DOMAIN_ZH.get(item['control_domain'], item['control_domain'])} | {' → '.join(item['nodes'])} |")
    return "\n".join(lines) + "\n"
