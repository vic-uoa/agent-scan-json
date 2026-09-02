from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import json
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from agent_json_workflow_scan.parser import parse_workflow  # noqa: E402
from agent_json_workflow_scan.pipeline import run_scan  # noqa: E402
from agent_json_workflow_scan.engine import execute_rules  # noqa: E402
from agent_json_workflow_scan.models import Edge, Node, NodeType, VariableRef, WorkflowIR  # noqa: E402
from agent_json_workflow_scan.report import render_risk_chain_svg, render_workflow_svg  # noqa: E402


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = ROOT / "tests" / "fixtures"
        self.rules = ROOT / "rules" / "core-rules.yml"

    def test_contract_types_and_nested_loop_are_parsed(self) -> None:
        ir, _ = parse_workflow(self.fixtures / "contract-workflow.json")
        self.assertEqual(len(ir.nodes), 16)
        self.assertEqual(len(ir.edges), 5)
        self.assertFalse([gap for gap in ir.coverage_gaps if gap["reason"] == "unsupported_node_type"])
        agent = ir.node_map()["AGENT-a"]
        self.assertEqual(len(agent.tool_specs), 2)
        self.assertIn("AUTONOMOUS_PLANNING", agent.capabilities)
        loop_model = ir.node_map()["LOOP-model"]
        self.assertEqual(loop_model.variable_refs[0].producer_node_id, "LOOP-start")
        self.assertEqual(loop_model.variable_refs[0].resolution, "symbol")

    def test_plain_code_transform_is_not_dangerous(self) -> None:
        ir, _ = parse_workflow(self.fixtures / "contract-workflow.json")
        self.assertNotIn("DANGEROUS_CODE_PRIMITIVE", ir.node_map()["CODE-safe"].capabilities)

    def test_numeric_string_retrieval_count_matches_platform_contract(self) -> None:
        ir, _ = parse_workflow(self.fixtures / "contract-workflow.json")
        _, findings, _ = execute_rules(ir, self.rules)
        knowledge_rules = {rule for item in findings if "KNOW-p" in item.node_ids for rule in [item.rule_id, *item.related_rule_ids]}
        self.assertNotIn("KB-006", knowledge_rules)

    def test_condition_source_index_may_be_ordinal_for_handle_id(self) -> None:
        nodes = [
            Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [{"name": "x", "type": "String", "maxLength": 20}]}),
            Node("judge", "JUDGE", NodeType.CONDITION.value, "条件", "/nodes/1", {"conditionList": [
                {"name": "IF", "handleId": 0, "subConditions": [{"name": "x", "condition": "EQ", "value": "a"}]},
                {"name": "ELSEIF2", "handleId": 2, "subConditions": [{"name": "x", "condition": "EQ", "value": "b"}]},
            ]}),
            Node("out-a", "TEMPLATE", NodeType.OUTPUT.value, "输出A", "/nodes/2", {"outputType": "Object", "output": [{"name": "result", "type": "String"}]}),
            Node("out-b", "TEMPLATE", NodeType.OUTPUT.value, "输出B", "/nodes/3", {"outputType": "Object", "output": [{"name": "result", "type": "String"}]}),
        ]
        edges = [
            Edge("e0", "start", "judge", source_handle="source", source_index=0),
            Edge("e1", "judge", "out-a", source_handle="el-right-judge-0", source_index=0),
            Edge("e2", "judge", "out-b", source_handle="el-right-judge-2", source_index=1),
        ]
        ir = WorkflowIR("ordinal", "hash", "test", nodes, edges, [], [], {})
        _, findings, _ = execute_rules(ir, self.rules)
        self.assertNotIn("FLOW-014", {rule for item in findings for rule in [item.rule_id, *item.related_rule_ids]})

    def test_read_only_fixed_rag_is_not_multiplied_into_high_risks(self) -> None:
        input_ref = VariableRef("start", "question", "model", "/nodes/2/data/prompt", "prompt")
        knowledge_ref = VariableRef("kb", "history", "model", "/nodes/2/data/prompt", "prompt")
        output_ref = VariableRef("model", "answer", "out", "/nodes/3/data/output/0", "result")
        nodes = [
            Node("start", "HEAD", NodeType.INPUT.value, "开始", "/nodes/0", {"paramList": [{"name": "question", "type": "String", "required": True}]}),
            Node("kb", "NEW_KNOWLEDGE", NodeType.KNOWLEDGE.value, "固定只读知识库", "/nodes/1", {
                "recallToolConfig": [{"knowledgeCode": "18880", "reCallNum": "1"}],
                "serviceConfig": {"recallCount": "1", "sortScore": 0.3, "whetherKnlSource": False},
            }),
            Node("model", "MODEL", NodeType.LLM.value, "质检模型", "/nodes/2", {
                "prompt": "输入：${question}\n参考数据：${history}",
                "modelConfig": {"maxNewToken": 1024},
            }, variable_refs=[input_ref, knowledge_ref]),
            Node("out", "TEMPLATE", NodeType.OUTPUT.value, "结束", "/nodes/3", {
                "outputType": "Object", "output": [{"name": "result", "type": "String"}], "isStreamingOutput": False,
            }, variable_refs=[output_ref]),
        ]
        edges = [Edge("e0", "start", "kb"), Edge("e1", "kb", "model"), Edge("e2", "model", "out")]
        ir = WorkflowIR("rag", "hash", "test", nodes, edges, [input_ref, knowledge_ref, output_ref], [], {})
        _, findings, _ = execute_rules(ir, self.rules)
        rules = {rule for item in findings for rule in [item.rule_id, *item.related_rule_ids]}
        self.assertFalse({"KB-002", "LLM-005", "OUT-004", "OUT-005", "TOOL-006"} & rules)
        risk_findings = [item for item in findings if item.report_group == "risk"]
        self.assertEqual(len(risk_findings), 1)
        self.assertEqual(risk_findings[0].severity, "LOW")
        self.assertTrue({"IN-004", "LLM-001", "KB-003"}.issubset({risk_findings[0].rule_id, *risk_findings[0].related_rule_ids}))

    def test_envelope_schema_rejects_malformed_node(self) -> None:
        with TemporaryDirectory() as tmp:
            malformed = Path(tmp) / "malformed.json"
            malformed.write_text(json.dumps({"nodes": [{"id": "missing-data"}], "edges": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "envelope schema violation"):
                parse_workflow(malformed)

    def test_unmapped_future_field_is_not_silently_ignored(self) -> None:
        with TemporaryDirectory() as tmp:
            future = Path(tmp) / "future.json"
            future.write_text(json.dumps({"nodes": [{"id": "m", "type": "MODEL", "data": {"type": "MODEL", "futureSecurityMode": True}}], "edges": []}), encoding="utf-8")
            ir, _ = parse_workflow(future)
            self.assertIn("unmapped_node_field", {gap["reason"] for gap in ir.coverage_gaps})
            result = run_scan(dsl_path=future, output_dir=Path(tmp) / "out", rules_path=self.rules, mode="structure-only")
            self.assertEqual(result["completeness_result"], "INCOMPLETE")
            self.assertGreater(result["scanner_gap_count"], 0)

    def test_known_model_runtime_fields_are_mapped(self) -> None:
        with TemporaryDirectory() as tmp:
            workflow = Path(tmp) / "known-fields.json"
            workflow.write_text(json.dumps({"nodes": [{
                "id": "m", "type": "MODEL", "data": {
                    "type": "MODEL", "context": "session", "defaultOutput": "fallback",
                    "ignoreException": False,
                },
            }], "edges": []}), encoding="utf-8")
            ir, _ = parse_workflow(workflow)
            unmapped = {gap.get("field") for gap in ir.coverage_gaps if gap["reason"] == "unmapped_node_field"}
            self.assertFalse({"context", "defaultOutput", "ignoreException"} & unmapped)

    def test_output_name_path_alias_resolves_and_type_mismatch_is_reported(self) -> None:
        with TemporaryDirectory() as tmp:
            workflow = Path(tmp) / "alias-type.json"
            workflow.write_text(json.dumps({
                "nodes": [
                    {"id": "model", "type": "MODEL", "data": {
                        "type": "MODEL", "label": "图像模型", "outputName": "imgAI", "outputType": "Object",
                        "output": [{"name": "content", "type": "Object", "sub": [
                            {"name": "result", "type": "Object", "sub": [
                                {"name": "choices", "type": "Array<String>"},
                            ]},
                        ]}],
                    }},
                    {"id": "out", "type": "TEMPLATE", "data": {
                        "type": "TEMPLATE", "label": "结果", "outputType": "Object",
                        "output": [{"name": "answer", "type": "String", "variableType": "REFERENCE", "variable": "imgAI.content.result.choices"}],
                    }},
                ],
                "edges": [{"id": "e1", "source": "model", "target": "out"}],
            }), encoding="utf-8")
            ir, _ = parse_workflow(workflow)
            self.assertFalse([gap for gap in ir.coverage_gaps if gap["reason"] == "unresolved_symbol"])
            ref = ir.node_map()["out"].variable_refs[0]
            self.assertEqual((ref.producer_node_id, ref.variable_name, ref.resolution), ("model", "content.result.choices", "symbol_path"))
            self.assertEqual(len(ir.raw_metadata["reference_type_mismatches"]), 1)
            _, findings, _ = execute_rules(ir, self.rules)
            finding_rules = {rule for item in findings for rule in [item.rule_id, *item.related_rule_ids]}
            self.assertIn("FLOW-017", finding_rules)

    def test_python_return_type_is_checked_against_declared_output(self) -> None:
        with TemporaryDirectory() as tmp:
            workflow = Path(tmp) / "code-return.json"
            workflow.write_text(json.dumps({"nodes": [{
                "id": "code", "type": "CODE", "data": {
                    "type": "CODE", "label": "转换", "language": "python", "outputType": "String",
                    "code": "def handler(params):\n    return {'ok': True}\n",
                },
            }], "edges": []}), encoding="utf-8")
            ir, _ = parse_workflow(workflow)
            self.assertEqual(ir.raw_metadata["code_return_mismatches"][0]["inferred_types"], ["OBJECT"])
            _, findings, _ = execute_rules(ir, self.rules)
            finding_rules = {rule for item in findings for rule in [item.rule_id, *item.related_rule_ids]}
            self.assertIn("TOOL-013", finding_rules)

    def test_code_local_param_lookup_is_not_guessed_as_global_symbol(self) -> None:
        with TemporaryDirectory() as tmp:
            workflow = Path(tmp) / "local-param.json"
            workflow.write_text(json.dumps({"nodes": [{
                "id": "code", "type": "CODE", "data": {
                    "type": "CODE", "language": "python",
                    "code": "def handler(params):\n    return {'name': params.get('name')}\n",
                },
            }], "edges": []}), encoding="utf-8")
            ir, _ = parse_workflow(workflow)
            self.assertFalse([gap for gap in ir.coverage_gaps if gap["reason"] == "unresolved_symbol"])

    def test_nested_url_field_in_whole_object_reference_reaches_ssrf_rule(self) -> None:
        with TemporaryDirectory() as tmp:
            workflow = Path(tmp) / "nested-url.json"
            workflow.write_text(json.dumps({
                "nodes": [
                    {"id": "start", "type": "HEAD", "data": {
                        "type": "HEAD", "outputName": "systemInput", "paramList": [{
                            "name": "payload", "type": "Object", "sub": [{"name": "image_url", "type": "String"}],
                        }],
                    }},
                    {"id": "plugin", "type": "AI_PLUGIN", "data": {
                        "type": "AI_PLUGIN", "label": "图像抓取", "urlMethod": "POST", "pluginKey": "image-reader",
                        "body": [{"name": "request", "type": "Object", "variableType": "REFERENCE", "variable": "systemInput.payload"}],
                    }},
                ],
                "edges": [{"id": "e1", "source": "start", "target": "plugin"}],
            }), encoding="utf-8")
            ir, _ = parse_workflow(workflow)
            _, findings, _ = execute_rules(ir, self.rules)
            finding_rules = {rule for item in findings for rule in [item.rule_id, *item.related_rule_ids]}
            self.assertIn("TOOL-003", finding_rules)

    def test_dangerous_code_calls_are_classified_by_primitive_family(self) -> None:
        with TemporaryDirectory() as tmp:
            workflow = Path(tmp) / "code.json"
            workflow.write_text(json.dumps({"nodes": [{"id": "c", "type": "CODE", "data": {"type": "CODE", "language": "python", "code": "def handler(params):\n    return requests.get(params.get('url')).text\n"}}], "edges": []}), encoding="utf-8")
            ir, _ = parse_workflow(workflow)
            capabilities = ir.node_map()["c"].capabilities
            self.assertIn("CODE_NETWORK", capabilities)
            self.assertNotIn("CODE_DYNAMIC_EXEC", capabilities)

    def test_safe_structure_scan_passes(self) -> None:
        with TemporaryDirectory() as tmp:
            result = run_scan(dsl_path=self.fixtures / "safe-workflow.json", output_dir=Path(tmp), rules_path=self.rules, mode="structure-only")
            self.assertEqual(result["quality_gate"], "PASS")
            self.assertEqual(result["risk_gate"], "PASS")
            self.assertEqual(result["completeness_result"], "COMPLETE")
            self.assertEqual(result["finding_count"], 0)

    def test_risky_scan_fails_and_preserves_raw_matches(self) -> None:
        with TemporaryDirectory() as tmp:
            output = Path(tmp)
            result = run_scan(dsl_path=self.fixtures / "risky-workflow.json", output_dir=output, rules_path=self.rules, mode="structure-only")
            self.assertEqual(result["quality_gate"], "FAIL")
            findings = result["_findings"]
            rule_ids = {rule for item in findings for rule in [item.rule_id, *item.related_rule_ids]}
            self.assertIn("FLOW-009", rule_ids)
            self.assertIn("LLM-003", rule_ids)
            self.assertTrue(result["_verification"]["passed"])
            report_path = output / "risky-workflow" / "risky-workflow-安全扫描报告.html"
            self.assertEqual(report_path.resolve(), Path(result["report_path"]))
            self.assertEqual([report_path], list(report_path.parent.iterdir()))

    def test_html_report_is_chinese_first_and_embeds_visualizations(self) -> None:
        with TemporaryDirectory() as tmp:
            output = Path(tmp)
            result = run_scan(dsl_path=self.fixtures / "risky-workflow.json", output_dir=output, rules_path=self.rules, mode="structure-only")
            report_html = Path(result["report_path"]).read_text(encoding="utf-8")

            for label in (
                "安全扫描报告", "发布门禁", "扫描完整性", "工作流图", "风险与逻辑链",
                "对应逻辑链", "证据状态", "控制域", "修复建议", "扫描边界",
            ):
                self.assertIn(label, report_html)
            self.assertIn("<svg", report_html)
            self.assertIn("LLM-003", report_html)
            self.assertNotIn("report.md", report_html)
            self.assertNotIn("workflow-ir.json", report_html)
            self.assertNotIn("structured_data_contract", report_html)
            machine_report = result["_report"]
            self.assertIn(machine_report["summary"]["quality_gate"], {"PASS", "REVIEW", "FAIL"})
            self.assertIn(machine_report["summary"]["completeness_result"], {"COMPLETE", "RUNTIME_EVIDENCE_REQUIRED", "INCOMPLETE"})
            self.assertTrue(machine_report["workflow"]["nodes"])
            self.assertTrue(machine_report["workflow"]["edges"])

    def test_visuals_preserve_canvas_layout_and_focus_risk_chains(self) -> None:
        workflow = {
            "nodes": [
                {"id": "start", "title": "用户输入", "type": "INPUT", "position": {"x": 0, "y": 100}},
                {"id": "route", "title": "状态判断", "type": "CONDITION", "position": {"x": 300, "y": 100}, "condition_subject": "状态解析", "condition_case_count": 1, "branch_conditions": {"0": "状态 等于「通过」", "false": "否则"}},
                {"id": "yes", "title": "通过处理", "type": "LLM", "position": {"x": 600, "y": 0}},
                {"id": "no", "title": "拒绝处理", "type": "OUTPUT", "position": {"x": 600, "y": 220}},
            ],
            "edges": [
                {"source": "start", "target": "route", "source_index": 0},
                {"source": "route", "target": "yes", "source_index": 0},
                {"source": "route", "target": "no", "source_handle": "false", "source_index": 1},
            ],
        }
        full_svg = render_workflow_svg(workflow, [], "canvas-test")
        self.assertIn('data-layout="dsl-canvas"', full_svg)
        self.assertIn("状态 等于「通过」", full_svg)
        self.assertIn("否则", full_svg)
        self.assertIn("条件 1", full_svg)
        focus_svg = render_risk_chain_svg(workflow, ["start", "route", "yes"], "focus-test", "MEDIUM")
        self.assertIn("用户输入", focus_svg)
        self.assertIn("状态判断", focus_svg)
        self.assertIn("通过处理", focus_svg)
        self.assertNotIn("拒绝处理", focus_svg)
        self.assertIn("#a86508", focus_svg)

    def test_assessment_requires_hash_and_generates_cluster(self) -> None:
        dsl = self.fixtures / "safe-workflow.json"
        ir, _ = parse_workflow(dsl)
        with TemporaryDirectory() as tmp:
            temp = Path(tmp)
            samples = temp / "samples.json"
            samples.write_text(json.dumps({
                "confirmed_by_user": True,
                "confirmed_dsl_sha256": ir.workflow_hash,
                "samples": [{"sample_id": "S1", "input": {"question": "hello"}, "expected_business_intent": "answer safely"}],
            }), encoding="utf-8")
            output = temp / "out"
            result = run_scan(dsl_path=dsl, samples_path=samples, output_dir=output, rules_path=self.rules, mode="assessment")
            cluster = result["_test_cluster"]
            self.assertGreaterEqual(len(cluster["cases"]), 4)
            self.assertTrue(cluster["generation_audit"]["all_cases_not_executed"])

    def test_model_advisory_can_only_add_validated_inert_cases(self) -> None:
        dsl = self.fixtures / "risky-workflow.json"
        ir, _ = parse_workflow(dsl)
        _, findings, _ = execute_rules(ir, self.rules)
        target_finding = next(item for item in findings if item.node_ids)
        with TemporaryDirectory() as tmp:
            temp = Path(tmp)
            samples = temp / "samples.json"
            samples.write_text(json.dumps({
                "confirmed_by_user": True,
                "confirmed_dsl_sha256": ir.workflow_hash,
                "samples": [{"sample_id": "S1", "input": {"question": "normal"}, "expected_business_intent": "answer safely"}],
            }), encoding="utf-8")
            proposal = temp / "advisory.json"
            proposal.write_text(json.dumps({
                "generated_by": "test-model",
                "executive_summary": "Non-authoritative wording.",
                "cases": [{
                    "case_id": "MODEL-CASE-1",
                    "seed_sample_ids": ["S1"],
                    "finding_ids": [target_finding.id],
                    "target_nodes": [target_finding.node_ids[-1]],
                    "rule_ids": [target_finding.rule_id],
                    "attack_techniques": ["defensive_hypothesis"],
                    "input": {"question": "normal\n[INERT_SECURITY_TEST] model proposal"},
                    "derivation": "Additional inert variation.",
                    "expected_security_invariants": ["Preserve authorization."],
                    "forbidden_effects": ["No real side effect."],
                    "oracle_source": "model_proposal",
                    "execution_status": "NOT_EXECUTED"
                }]
            }), encoding="utf-8")
            output = temp / "out"
            result = run_scan(dsl_path=dsl, samples_path=samples, model_advisory_path=proposal, output_dir=output, rules_path=self.rules, mode="assessment")
            advisory = result["_model_advisory"]
            self.assertEqual(result["quality_gate"], "FAIL")
            self.assertEqual(advisory["accepted_case_ids"], ["MODEL-CASE-1"])
            self.assertFalse(advisory["authoritative"])


if __name__ == "__main__":
    unittest.main()
