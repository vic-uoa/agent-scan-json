from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from agent_json_workflow_scan.engine import RuleCatalog, execute_rules  # noqa: E402
from agent_json_workflow_scan.models import Edge, Node, NodeType, VariableRef, WorkflowIR  # noqa: E402


def spec(*, method: str = "GET", auth: bool = True, output_schema: bool = True, version: int | None = 1) -> dict:
    return {
        "kind": "api_plugin",
        "method": method,
        "auth_declared": auth,
        "has_output_schema": output_schema,
        "version": version,
        "parameters": [],
    }


def rule_ids(findings) -> set[str]:
    return {rule for item in findings for rule in [item.rule_id, *item.related_rule_ids]}


class RuleApplicabilityMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = ROOT / "rules" / "core-rules.yml"

    def execute(self, nodes: list[Node], edges: list[Edge], refs: list[VariableRef] | None = None):
        ir = WorkflowIR("matrix", "hash", "test", nodes, edges, refs or [], [], {})
        return execute_rules(ir, self.rules)[1]

    def test_every_rule_has_exactly_one_applicability_policy(self) -> None:
        catalog = RuleCatalog(self.rules)
        self.assertEqual(set(catalog.rules), set(catalog.applicability))
        self.assertEqual(len(catalog.rules), 54)

    def test_free_text_model_to_effectful_tool_stays_high_signal(self) -> None:
        in_ref = VariableRef("start", "question", "model", "/nodes/1/prompt", "prompt")
        tool_ref = VariableRef("model", "answer", "tool", "/nodes/2/body", "body.command")
        nodes = [
            Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [{"name": "question", "type": "String", "maxLength": 100}]}),
            Node("model", "MODEL", NodeType.LLM.value, "模型", "/nodes/1", {"prompt": "${question}", "outputFormat": "text", "modelConfig": {"maxNewToken": 100}, "fallback": "fail_closed"}, variable_refs=[in_ref]),
            Node("tool", "API_PLUGIN", NodeType.TOOL.value, "写操作", "/nodes/2", {"timeout": 3, "signature": "trusted"}, tool_specs=[spec(method="POST")], variable_refs=[tool_ref], external=True, effectful=True, high_impact=True),
            Node("out", "TEMPLATE", NodeType.OUTPUT.value, "结束", "/nodes/3", {"outputType": "Object", "output": [{"name": "result", "type": "String"}]}),
        ]
        findings = self.execute(nodes, [Edge("e0", "start", "model"), Edge("e1", "model", "tool"), Edge("e2", "tool", "out")], [in_ref, tool_ref])
        ids = rule_ids(findings)
        self.assertTrue({"FLOW-009", "LLM-003", "TOOL-002"}.issubset(ids))
        self.assertTrue(any(item.severity == "HIGH" and item.report_group == "risk" for item in findings if item.rule_id in {"FLOW-009", "LLM-003"}))

    def test_structured_model_output_suppresses_free_text_control_rules(self) -> None:
        tool_ref = VariableRef("model", "command", "tool", "/nodes/2/body", "body.command")
        nodes = [
            Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [{"name": "question", "type": "String", "maxLength": 100}]}),
            Node("model", "MODEL", NodeType.LLM.value, "模型", "/nodes/1", {"outputFormat": "object", "output": [{"name": "command", "type": "String"}], "modelConfig": {"maxNewToken": 100}, "fallback": "fail_closed"}),
            Node("tool", "API_PLUGIN", NodeType.TOOL.value, "写操作", "/nodes/2", {"timeout": 3, "signature": "trusted"}, tool_specs=[spec(method="POST")], variable_refs=[tool_ref], external=True, effectful=True),
            Node("out", "TEMPLATE", NodeType.OUTPUT.value, "结束", "/nodes/3", {"outputType": "Object", "output": [{"name": "result", "type": "String"}]}),
        ]
        findings = self.execute(nodes, [Edge("e0", "start", "model"), Edge("e1", "model", "tool"), Edge("e2", "tool", "out")], [tool_ref])
        self.assertFalse({"FLOW-009", "LLM-003"} & rule_ids(findings))

    def test_json_declaration_without_field_schema_is_not_treated_as_strict_contract(self) -> None:
        tool_ref = VariableRef("model", "command", "tool", "/nodes/2/body", "body.command")
        nodes = [
            Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [{"name": "question", "type": "String", "maxLength": 100}]}),
            Node("model", "MODEL", NodeType.LLM.value, "模型", "/nodes/1", {"outputFormat": "json", "modelConfig": {"maxNewToken": 100}, "fallback": "fail_closed"}),
            Node("tool", "API_PLUGIN", NodeType.TOOL.value, "写操作", "/nodes/2", {"timeout": 3, "signature": "trusted"}, tool_specs=[spec(method="POST")], variable_refs=[tool_ref], external=True, effectful=True),
            Node("out", "TEMPLATE", NodeType.OUTPUT.value, "结束", "/nodes/3", {"outputType": "Object", "output": [{"name": "result", "type": "String"}]}),
        ]
        findings = self.execute(nodes, [Edge("e0", "start", "model"), Edge("e1", "model", "tool"), Edge("e2", "tool", "out")], [tool_ref])
        self.assertTrue({"FLOW-009", "LLM-003", "OUT-006"}.issubset(rule_ids(findings)))
        schema_gap = next(item for item in findings if "LLM-003" in {item.rule_id, *item.related_rule_ids})
        self.assertEqual(schema_gap.status, "COVERAGE_GAP")

    def test_plain_streaming_output_is_not_rich_text_by_default(self) -> None:
        nodes = [
            Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [{"name": "x", "type": "String", "maxLength": 20}]}),
            Node("out", "TEMPLATE", NodeType.OUTPUT.value, "结束", "/nodes/1", {"outputType": "String", "isStreamingOutput": True}),
        ]
        self.assertNotIn("OUT-004", rule_ids(self.execute(nodes, [Edge("e0", "start", "out")])))

    def test_missing_exported_schema_is_a_gap_but_malformed_schema_is_confirmed(self) -> None:
        no_schema = Node("model", "MODEL", NodeType.LLM.value, "模型", "/nodes/0", {"outputFormat": "json"})
        gap = next(item for item in self.execute([no_schema], []) if item.rule_id == "OUT-006")
        self.assertEqual(gap.status, "COVERAGE_GAP")
        malformed = Node("model", "MODEL", NodeType.LLM.value, "模型", "/nodes/0", {"outputFormat": "json", "output": [{"name": "result"}, {"name": "result", "type": "String"}]})
        confirmed = next(item for item in self.execute([malformed], []) if item.rule_id == "OUT-006")
        self.assertEqual(confirmed.status, "CONFIRMED")

    def test_dynamic_network_target_requires_untrusted_binding(self) -> None:
        url_ref = VariableRef("start", "url", "tool", "/nodes/1/query", "query.url")
        base_nodes = [
            Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [{"name": "url", "type": "String", "maxLength": 200}]}),
            Node("tool", "API_PLUGIN", NodeType.TOOL.value, "读取", "/nodes/1", {"signature": "trusted"}, tool_specs=[spec(method="GET")], external=True),
            Node("out", "TEMPLATE", NodeType.OUTPUT.value, "结束", "/nodes/2", {"outputType": "Object", "output": [{"name": "result", "type": "String"}]}),
        ]
        edges = [Edge("e0", "start", "tool"), Edge("e1", "tool", "out")]
        self.assertNotIn("TOOL-003", rule_ids(self.execute(base_nodes, edges)))
        bound_nodes = [base_nodes[0], Node(**{**base_nodes[1].__dict__, "variable_refs": [url_ref]}), base_nodes[2]]
        self.assertIn("TOOL-003", rule_ids(self.execute(bound_nodes, edges, [url_ref])))

    def test_input_bounds_file_constraints_and_sensitive_classification_are_distinct(self) -> None:
        start = Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [
            {"name": "comment", "type": "String", "minLength": 1},
            {"name": "upload", "type": "File", "maxSize": 1024},
            {"name": "profile", "type": "Object"},
            {"name": "access_token", "type": "String", "maxLength": 80, "dataClassification": "secret"},
        ]})
        out = Node("out", "TEMPLATE", NodeType.OUTPUT.value, "结束", "/nodes/1", {"outputType": "Object", "output": [{"name": "result", "type": "String"}]})
        ids = rule_ids(self.execute([start, out], [Edge("e0", "start", "out")]))
        self.assertTrue({"IN-001", "IN-002", "IN-003"}.issubset(ids))
        self.assertNotIn("IN-005", ids)

    def test_invalid_retrieval_values_are_not_accepted_as_retrieval_bounds(self) -> None:
        knowledge = Node("kb", "NEW_KNOWLEDGE", NodeType.KNOWLEDGE.value, "客户知识库", "/nodes/0", {
            "recallToolConfig": [{"knowledgeCode": "fixed-${tenant}", "reCallNum": "zero"}],
            "serviceConfig": {"recallCount": -1, "sortScore": True},
        })
        findings = self.execute([knowledge], [])
        ids = rule_ids(findings)
        self.assertTrue({"KB-001", "KB-002", "KB-005", "KB-006"}.issubset(ids))
        kb_acl = next(item for item in findings if "KB-002" in {item.rule_id, *item.related_rule_ids})
        self.assertEqual(kb_acl.status, "COVERAGE_GAP")

    def test_runtime_gaps_are_aggregated_by_control_domain(self) -> None:
        nodes = [
            Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [{"name": "x", "type": "String", "maxLength": 20}]}),
            Node("a", "API_PLUGIN", NodeType.TOOL.value, "写A", "/nodes/1", {}, tool_specs=[spec(method="POST", auth=False, version=None)], external=True, effectful=True),
            Node("b", "API_PLUGIN", NodeType.TOOL.value, "写B", "/nodes/2", {}, tool_specs=[spec(method="POST", auth=False, version=None)], external=True, effectful=True),
            Node("out", "TEMPLATE", NodeType.OUTPUT.value, "结束", "/nodes/3", {"outputType": "Object", "output": [{"name": "result", "type": "String"}]}),
        ]
        findings = self.execute(nodes, [Edge("e0", "start", "a"), Edge("e1", "a", "b"), Edge("e2", "b", "out")])
        auth_gaps = [item for item in findings if item.report_group == "coverage_gap" and "TOOL-005" in {item.rule_id, *item.related_rule_ids}]
        self.assertEqual(len(auth_gaps), 1)
        self.assertEqual(set(auth_gaps[0].node_ids), {"a", "b"})

    def test_guarded_and_bypass_paths_are_distinguished(self) -> None:
        nodes = [
            Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [{"name": "x", "type": "String", "maxLength": 20}]}),
            Node("guard", "JUDGE", NodeType.CONDITION.value, "授权校验", "/nodes/1", {"conditionList": [{"name": "IF", "handleId": 0, "subConditions": [{"name": "approved", "condition": "EQ", "value": True}]}]}),
            Node("tool", "API_PLUGIN", NodeType.TOOL.value, "付款", "/nodes/2", {"timeout": 3, "signature": "trusted"}, tool_specs=[spec(method="POST")], external=True, effectful=True, high_impact=True),
            Node("out", "TEMPLATE", NodeType.OUTPUT.value, "结束", "/nodes/3", {"outputType": "Object", "output": [{"name": "result", "type": "String"}]}),
        ]
        guarded_edges = [Edge("e0", "start", "guard"), Edge("e1", "guard", "tool", source_handle="guard-0", source_index=0), Edge("e2", "tool", "out")]
        self.assertFalse({"FLOW-004", "FLOW-006"} & rule_ids(self.execute(nodes, guarded_edges)))
        bypass_edges = [*guarded_edges, Edge("e3", "start", "tool")]
        self.assertIn("FLOW-006", rule_ids(self.execute(nodes, bypass_edges)))

    def test_approval_name_without_an_affirmative_branch_is_not_a_gate(self) -> None:
        nodes = [
            Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [{"name": "x", "type": "String", "maxLength": 20}]}),
            Node("named-only", "JUDGE", NodeType.CONDITION.value, "授权审批", "/nodes/1", {"conditionList": [{"name": "IF", "handleId": 0, "subConditions": [{"name": "route", "condition": "EQ", "value": "go"}]}]}),
            Node("tool", "API_PLUGIN", NodeType.TOOL.value, "付款", "/nodes/2", {"timeout": 3, "signature": "trusted"}, tool_specs=[spec(method="POST")], external=True, effectful=True, high_impact=True),
            Node("out", "TEMPLATE", NodeType.OUTPUT.value, "结束", "/nodes/3", {"outputType": "Object", "output": [{"name": "result", "type": "String"}]}),
        ]
        edges = [Edge("e0", "start", "named-only"), Edge("e1", "named-only", "tool", source_handle="named-only-0", source_index=0), Edge("e2", "tool", "out")]
        self.assertIn("FLOW-004", rule_ids(self.execute(nodes, edges)))

    def test_role_based_authorization_branch_is_a_valid_action_gate(self) -> None:
        nodes = [
            Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [{"name": "x", "type": "String", "maxLength": 20}]}),
            Node("role-gate", "JUDGE", NodeType.CONDITION.value, "权限校验", "/nodes/1", {"conditionList": [{"name": "IF", "handleId": 0, "subConditions": [{"name": "userRole", "condition": "EQ", "value": "admin"}]}]}),
            Node("tool", "API_PLUGIN", NodeType.TOOL.value, "付款", "/nodes/2", {"timeout": 3, "signature": "trusted"}, tool_specs=[spec(method="POST")], external=True, effectful=True, high_impact=True),
            Node("out", "TEMPLATE", NodeType.OUTPUT.value, "结束", "/nodes/3", {"outputType": "Object", "output": [{"name": "result", "type": "String"}]}),
        ]
        edges = [Edge("e0", "start", "role-gate"), Edge("e1", "role-gate", "tool", source_handle="role-gate-0", source_index=0), Edge("e2", "tool", "out")]
        self.assertFalse({"FLOW-004", "FLOW-006"} & rule_ids(self.execute(nodes, edges)))

    def test_tool_output_only_escalates_when_it_reaches_effect(self) -> None:
        tool_to_model = VariableRef("reader", "content", "model", "/nodes/2/prompt", "prompt")
        base = [
            Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [{"name": "q", "type": "String", "maxLength": 20}]}),
            Node("reader", "API_PLUGIN", NodeType.TOOL.value, "外部读取", "/nodes/1", {"signature": "trusted"}, tool_specs=[spec(method="GET")], external=True),
            Node("model", "MODEL", NodeType.LLM.value, "模型", "/nodes/2", {"prompt": "${content}", "modelConfig": {"maxNewToken": 100}}, variable_refs=[tool_to_model]),
            Node("out", "TEMPLATE", NodeType.OUTPUT.value, "结束", "/nodes/3", {"outputType": "Object", "output": [{"name": "result", "type": "String"}]}),
        ]
        edges = [Edge("e0", "start", "reader"), Edge("e1", "reader", "model"), Edge("e2", "model", "out")]
        findings = self.execute(base, edges, [tool_to_model])
        self.assertIn("TOOL-009", rule_ids(findings))
        self.assertNotIn("FLOW-005", rule_ids(findings))
        model_to_writer = VariableRef("model", "answer", "writer", "/nodes/3/body", "body.command")
        writer = Node("writer", "API_PLUGIN", NodeType.TOOL.value, "外部写入", "/nodes/3", {"timeout": 3, "signature": "trusted"}, tool_specs=[spec(method="POST")], variable_refs=[model_to_writer], external=True, effectful=True)
        out = Node("out", "TEMPLATE", NodeType.OUTPUT.value, "结束", "/nodes/4", {"outputType": "Object", "output": [{"name": "result", "type": "String"}]})
        extended = [*base[:3], writer, out]
        extended_edges = [Edge("e0", "start", "reader"), Edge("e1", "reader", "model"), Edge("e2", "model", "writer"), Edge("e3", "writer", "out")]
        self.assertIn("FLOW-005", rule_ids(self.execute(extended, extended_edges, [tool_to_model, model_to_writer])))

    def test_human_text_output_is_hardening_but_high_trust_output_is_risk(self) -> None:
        start = Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [{"name": "x", "type": "String", "maxLength": 20}]})
        human = Node("out", "TEMPLATE", NodeType.OUTPUT.value, "显示回答", "/nodes/1", {"outputType": "String"})
        findings = self.execute([start, human], [Edge("e0", "start", "out")])
        output_item = next(item for item in findings if "OUT-001" in {item.rule_id, *item.related_rule_ids})
        self.assertEqual(output_item.report_group, "hardening")
        trusted = Node("out", "TEMPLATE", NodeType.OUTPUT.value, "自动决策结果", "/nodes/1", {"outputType": "String", "machineConsumed": True})
        findings = self.execute([start, trusted], [Edge("e0", "start", "out")])
        output_item = next(item for item in findings if "OUT-001" in {item.rule_id, *item.related_rule_ids})
        self.assertEqual(output_item.report_group, "risk")
        self.assertEqual(output_item.status, "PROBABLE")


if __name__ == "__main__":
    unittest.main()
