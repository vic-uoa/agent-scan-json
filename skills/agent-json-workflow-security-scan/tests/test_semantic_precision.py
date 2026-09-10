"""Static security regressions: payload strings are never executed or transmitted."""
from pathlib import Path
from datetime import datetime, timedelta, timezone
from tempfile import TemporaryDirectory
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from agent_json_workflow_scan.engine import GraphIndex, RuleCatalog, SecurityEngine, execute_rules
from agent_json_workflow_scan.models import Edge, Node, VariableRef, WorkflowIR
from agent_json_workflow_scan.parser import parse_workflow
from agent_json_workflow_scan.pipeline import apply_waivers, quality_gate, run_scan
from agent_json_workflow_scan.semantics import analyze_python, contains_secret, field_matches


def parse(data):
    with TemporaryDirectory() as temp:
        path = Path(temp) / "precision.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return parse_workflow(path)[0]


def code_ir(code):
    return parse({"id": "code", "nodes": [
        {"id": "start", "data": {"type": "HEAD", "paramList": [{"name": "text", "type": "String", "maxLength": 100}]}},
        {"id": "code", "data": {"type": "CODE", "language": "python", "code": code,
            "input": [{"name": "text", "variable": "start.text", "variableType": "REFERENCE"}]}},
        {"id": "out", "data": {"type": "TEMPLATE", "outputType": "String"}},
    ], "edges": [{"source": "start", "target": "code"}, {"source": "code", "target": "out"}]})


def matches(ir):
    return execute_rules(ir, ROOT / "rules/core-rules.yml")[1]


def has_rule(findings, rule, group=None):
    return any(rule in {item.rule_id, *item.related_rule_ids} and (group is None or item.report_group == group) for item in findings)


class CodePrecisionTests(unittest.TestCase):
    def test_data_operations_comments_and_strings_are_not_execution(self):
        for code in [
            'import urllib.parse\ndef main(text):\n return urllib.parse.quote(text)',
            'import json\ndef main(text):\n return json.loads(text)',
            'def main(text):\n # eval(text)\n return "os.system(text)"',
        ]:
            with self.subTest(code=code):
                ir = code_ir(code)
                self.assertFalse(analyze_python(code).calls)
                self.assertFalse(has_rule(matches(ir), "TOOL-004", "risk"))

    def test_import_callable_alias_and_interpreter_arguments_are_detected(self):
        for code in [
            'import os as runtime\ndef main(text):\n runtime.system(text)',
            'from subprocess import run as launch\ndef main(text):\n launch(text, shell=True)',
            'def main(text):\n fn = eval\n return fn(text)',
            'import subprocess\ndef main(text):\n subprocess.run(["python", "-c", text])',
            'import pickle as p\ndef main(text):\n return p.loads(text)',
            'def main(text):\n return cursor.execute("SELECT x FROM t WHERE x=" + text)',
        ]:
            with self.subTest(code=code):
                findings = matches(code_ir(code))
                self.assertTrue(has_rule(findings, "TOOL-004", "risk"))
                risk = next(item for item in findings if item.rule_id == "TOOL-004" and item.report_group == "risk")
                self.assertEqual((risk.status, risk.severity), ("PROBABLE", "HIGH"))
                self.assertEqual(quality_gate(findings, {})["risk_gate_result"], "REVIEW")

    def test_fixed_argv_sql_bind_values_and_safe_yaml_do_not_become_injection(self):
        for code in [
            'import subprocess\ndef main(text):\n subprocess.run(["echo", text], shell=False)',
            'def main(text):\n cursor.execute("SELECT x FROM t WHERE id=?", (text,))',
            'import yaml\ndef main(text):\n return yaml.load(text, Loader=yaml.SafeLoader)',
            'def main(text):\n return eval("1+1")',
            'def main(text):\n return open("local.txt").read()',
        ]:
            with self.subTest(code=code):
                findings = matches(code_ir(code))
                self.assertFalse(has_rule(findings, "TOOL-004", "risk"))
                self.assertFalse(has_rule(findings, "FLOW-004", "risk"))

    def test_http_calls_check_target_not_query_values(self):
        for code in [
            'import requests\ndef main(text):\n return requests.get("https://service.invalid/", params={"q":text})',
            'import requests\ndef main(text):\n return requests.get(f"https://service.invalid/{text}")',
            'import urllib.request\ndef main(text):\n return urllib.request.urlopen("https://service.invalid/" + text)',
        ]:
            with self.subTest(code=code):
                findings = matches(code_ir(code))
                self.assertFalse(has_rule(findings, "TOOL-003", "risk"))
                self.assertFalse(has_rule(findings, "TOOL-004", "risk"))
        for code in [
            'import requests as r\ndef main(text):\n return r.get(text)',
            'from urllib.request import urlopen as fetch\ndef main(text):\n return fetch(text)',
            'import httpx\ndef main(text):\n return httpx.request("GET", text)',
            'import requests\ndef main(text):\n return requests.get(f"https://{text}/")',
        ]:
            with self.subTest(code=code):
                self.assertTrue(has_rule(matches(code_ir(code)), "TOOL-003", "risk"))

    def test_session_alias_is_not_lost(self):
        code = 'import requests as r\ndef main(text):\n session = r.Session()\n return session.get(text)'
        self.assertTrue(has_rule(matches(code_ir(code)), "TOOL-003", "risk"))

    def test_unknown_dispatch_and_syntax_remain_coverage_gaps(self):
        for code in ['def main(text):\n return text()', 'def main(text):\n return getattr(text, "run")()', 'def main(:',
                     'import internal_plugin\ndef main(text):\n return internal_plugin.run(text)']:
            with self.subTest(code=code):
                self.assertTrue(has_rule(matches(code_ir(code)), "TOOL-011", "coverage_gap"))

    def test_keyword_command_argument_is_not_lost(self):
        self.assertTrue(has_rule(matches(code_ir('import os\ndef main(text):\n os.system(command=text)')), "TOOL-004", "risk"))

    def test_later_or_conditional_assignment_cannot_sanitize_earlier_sink(self):
        for code in ['def main(text):\n eval(text)\n text = "1+1"',
                     'def main(text):\n if len(text) < 2:\n  text = "1+1"\n return eval(text)']:
            self.assertTrue(has_rule(matches(code_ir(code)), "TOOL-004", "risk"))

    def test_unknown_global_callable_alias_is_not_silently_safe(self):
        self.assertTrue(has_rule(matches(code_ir('fn = eval\ndef main(text):\n return fn(text)')), "TOOL-011", "coverage_gap"))

    def test_unsupported_code_is_scanner_incompleteness(self):
        findings = matches(code_ir('def main(text):\n return text()'))
        self.assertEqual(quality_gate(findings, {})["completeness_result"], "INCOMPLETE")

    def test_analysis_budget_is_visible(self):
        code = 'def main(text):\n' + ''.join(f' x{i} = x{i+1}\n' for i in range(80)) + ' x80 = eval\n return x0(text)'
        self.assertTrue(has_rule(matches(code_ir(code)), "TOOL-011", "coverage_gap"))

    def test_semantic_fact_has_call_location_without_code_payload(self):
        facts, _, _ = execute_rules(code_ir('def main(text):\n return eval(text)'), ROOT / "rules/core-rules.yml")
        fact = next(item for item in facts if item.kind == "TOOL-004")
        self.assertEqual(fact.data["semantic_evidence"]["line"], 2)
        self.assertEqual(fact.data["semantic_evidence"]["call"], "eval")
        self.assertEqual(fact.evidence, ["/nodes/1/data/code"])


class SecretPrecisionTests(unittest.TestCase):
    def test_placeholder_is_scoped_to_candidate(self):
        token = "ghp_" + "Ab12" * 9  # fabricated format-only fixture
        self.assertTrue(contains_secret("example documentation\n" + token))
        self.assertTrue(contains_secret("password=placeholder\npassword=Abc12345xyz"))
        self.assertTrue(contains_secret("password=hasexampleinside123"))
        for value in ["${TOKEN}", "{{ secrets.KEY }}", "your_api_key", "placeholder", "********"]:
            self.assertFalse(contains_secret(value, "apiKey"))

    def test_json_key_value_credentials_and_descriptor_values(self):
        self.assertTrue(contains_secret("AbC123456xyz", "apiKey"))
        self.assertTrue(contains_secret('"password": "AbC123456xyz"'))
        ir = parse({"nodes": [{"id": "tool", "data": {"type": "MCP", "header": [
            {"name": "apiKey", "value": "AbC123456xyz"}
        ]}}], "edges": []})
        self.assertIn("/nodes/0/data/header/0/value", ir.raw_metadata["secret_locations"])
        ir = parse({"nodes": [{"id": "tool", "data": {"type": "MCP", "header": [
            {"name": "ROOT.apiKey", "value": "start.secret", "variableType": "REFERENCE"}
        ]}}], "edges": []})
        self.assertFalse(ir.raw_metadata["secret_locations"])

    def test_node_pointer_prefix_does_not_attribute_node_ten_to_node_one(self):
        nodes = [{"id": f"model{i}", "data": {"type": "MODEL", "prompt": "fixed"}} for i in range(11)]
        nodes[10]["data"]["prompt"] = "ghp_" + "Ab12" * 9
        ir = parse({"nodes": nodes, "edges": []})
        secrets = [item for item in matches(ir) if "LLM-002" in {item.rule_id, *item.related_rule_ids}]
        self.assertEqual([item.node_ids for item in secrets], [["model10"]])

    def test_metadata_and_code_secrets_are_reported_without_serializing_values(self):
        token = "ghp_" + "Ab12" * 9
        data = {"apiKey": token, "nodes": [{"id": "code", "data": {"type": "CODE", "code": f'key = "{token}"'}}], "edges": []}
        ir = parse(data)
        self.assertTrue(has_rule(matches(ir), "TOOL-012", "risk"))
        with TemporaryDirectory() as temp:
            path = Path(temp) / "secret.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            result = run_scan(dsl_path=path, output_dir=Path(temp)/"out", rules_path=ROOT/"rules/core-rules.yml", mode="structure-only")
            self.assertNotIn(token, Path(result["report_path"]).read_text(encoding="utf-8"))


class GraphPrecisionTests(unittest.TestCase):
    def engine(self, nodes, refs=None, edges=None):
        ir = WorkflowIR("precision", "hash", "test", nodes, edges or [], refs or [], [], {})
        return SecurityEngine(ir, RuleCatalog(ROOT/"rules/core-rules.yml"))

    def test_long_paths_and_cycles_are_not_silently_truncated(self):
        nodes = [Node(str(i), "CODE", "CODE", str(i), f"/nodes/{i}") for i in range(90)]
        edges = [Edge(str(i), str(i), str(i+1)) for i in range(89)] + [Edge("cycle", "80", "20")]
        graph = self.engine(nodes, edges=edges).graph
        self.assertEqual(len(graph.path("0", "89", control_only=True)), 90)
        self.assertIsNone(graph.path("0", "89", control_only=True, excluded={"70"}))

    def test_path_selection_is_stable(self):
        nodes = [Node(i, "CODE", "CODE", i, f"/nodes/{i}") for i in ["s", "b", "a", "t"]]
        edges = [Edge("1", "s", "b"), Edge("2", "s", "a"), Edge("3", "a", "t"), Edge("4", "b", "t")]
        self.assertEqual(self.engine(nodes, edges=edges).graph.path("s", "t"), ["s", "a", "t"])

    def test_data_through_code_retains_untrusted_origin(self):
        first = VariableRef("start", "text", "code", "/nodes/1/data/input", "text")
        last = VariableRef("code", "result", "tool", "/nodes/2/data/query", "query.url")
        nodes = [Node("start", "HEAD", "INPUT", "start", "/nodes/0"),
                 Node("code", "CODE", "CODE", "code", "/nodes/1", variable_refs=[first]),
                 Node("tool", "MCP", "TOOL", "tool", "/nodes/2", variable_refs=[last])]
        engine = self.engine(nodes, [first, last])
        self.assertEqual(engine.untrusted_refs(nodes[-1], ["url"]), [last])
        self.assertEqual(self.engine(nodes, [last], [Edge("visual", "start", "code")]).untrusted_refs(nodes[-1], ["url"]), [])

    def test_unbound_sensitive_sibling_does_not_create_disclosure(self):
        start = Node("s", "HEAD", "INPUT", "s", "/nodes/0", {"paramList": [
            {"name": "question", "type": "String"}, {"name": "access_token", "type": "String"}]})
        ref = VariableRef("s", "question", "t", "/nodes/1/data/body", "body.text")
        tool = Node("t", "MCP", "TOOL", "t", "/nodes/1", variable_refs=[ref], external=True)
        engine = self.engine([start, tool], [ref])
        self.assertIsNone(engine.sensitive_path(start, tool))
        ref.variable_name = "access_token"
        self.assertEqual(engine.sensitive_path(start, tool), ["s", "t"])
        self.assertIsNone(engine.sensitive_path(tool, tool))

    def test_cascading_effects_require_control_edges(self):
        ref = VariableRef("a", "result", "b", "/nodes/1/data/body", "body")
        nodes = [Node("a", "MCP", "TOOL", "a", "/nodes/0", effectful=True),
                 Node("b", "MCP", "TOOL", "b", "/nodes/1", effectful=True, variable_refs=[ref])]
        self.assertFalse(has_rule(self.engine(nodes, [ref]).run()[1], "FLOW-010"))
        self.assertTrue(has_rule(self.engine(nodes, [ref], [Edge("1", "a", "b")]).run()[1], "FLOW-010"))

    def test_field_components_and_nested_leaf_do_not_taint_siblings(self):
        self.assertFalse(field_matches("", ["密钥", "token"]))
        self.assertTrue(field_matches("客户手机号", ["手机号", "token"]))
        for value in ["ghost", "security", "description", "suriname", "zipcode"]:
            self.assertFalse(field_matches(value, ["host", "uri", "script", "code"]))
        self.assertTrue(field_matches("body.callbackUrl", ["url"]))
        self.assertTrue(field_matches("body.projectId", ["projectid"]))
        start = Node("s", "HEAD", "INPUT", "s", "/nodes/0", {"paramList": [{"name": "obj", "type": "Object", "sub": [
            {"name": "image_url", "type": "String"}, {"name": "text", "type": "String"}]}]})
        ref = VariableRef("s", "obj.text", "t", "/nodes/1/data/body", "body.content")
        tool = Node("t", "MCP", "TOOL", "t", "/nodes/1", variable_refs=[ref])
        self.assertEqual(self.engine([start, tool], [ref]).untrusted_refs(tool, ["url"]), [])
        ref.variable_name = "obj"
        self.assertEqual(self.engine([start, tool], [ref]).untrusted_refs(tool, ["url"]), [ref])

    def gate(self, condition, refs=None, logic="AND", extra=None):
        start = Node("s", "HEAD", "INPUT", "s", "/nodes/0")
        gate = Node("g", "JUDGE", "CONDITION", "授权校验", "/nodes/1", {"conditionList": [{
            "handleId": 0, "logicalOperator": logic, "subConditions": [condition, *(extra or [])]}]})
        sink = Node("t", "MCP", "TOOL", "t", "/nodes/2", high_impact=True, effectful=True)
        engine = self.engine([start, gate, sink], refs, [Edge("1", "s", "g"), Edge("2", "g", "t", source_index=0, source_handle="g-0")])
        return engine._is_verified_action_gate_for_sink(gate, sink)

    def test_gate_negation_false_and_unrelated_boolean_cannot_sanitize(self):
        for condition in [{"name": "approved", "condition": "NE", "value": True},
                          {"name": "approved", "condition": "EQ", "value": False},
                          {"name": "route", "condition": "EQ", "value": True}]:
            self.assertFalse(self.gate(condition))

    def test_or_bypass_and_user_supplied_approval_cannot_sanitize(self):
        condition = {"name": "approved", "condition": "EQ", "value": True}
        bypass = {"name": "route", "condition": "EQ", "value": "go"}
        self.assertFalse(self.gate(condition, logic="OR", extra=[bypass]))
        self.assertTrue(self.gate(condition, logic="AND", extra=[bypass]))
        self.assertFalse(self.gate(condition, refs=[VariableRef("s", "approved", "g", "/nodes/1/data/conditionList", "approved")]))


class InputIntegrityTests(unittest.TestCase):
    def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected(self):
        for content in ['{"nodes": [], "nodes": [], "edges": []}', '{"nodes": [], "edges": [], "x": NaN}',
                        '{"nodes": [], "edges": [], "x": 1e999}',
                        '{"nodes": [], "edges": [], "x": {"auth": true, "auth": false}}']:
            with self.subTest(content=content), TemporaryDirectory() as temp:
                path = Path(temp)/"bad.json"
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    parse_workflow(path)

    def test_waivers_require_current_dsl_hash_and_valid_future_timezone(self):
        ir = parse({"apiKey": "ghp_" + "Ab12" * 9, "nodes": [], "edges": []})
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        for expiry, workflow_hash, accepted in [
            (future, ir.workflow_hash, True), (past, ir.workflow_hash, False),
            (future, None, False), (future, "other", False), ("not-a-date", ir.workflow_hash, False),
            ("2099-01-01T00:00:00", ir.workflow_hash, False),
        ]:
            with self.subTest(expiry=expiry, workflow_hash=workflow_hash):
                findings = matches(ir)
                finding = next(item for item in findings if item.rule_id == "TOOL-012")
                waiver = {"id": "w", "finding_id": finding.id, "approver": "reviewer", "justification": "fixture",
                          "expires_at": expiry, "workflow_hash": workflow_hash}
                audit = apply_waivers(findings, {"waivers": [waiver]}, ir.workflow_hash)
                self.assertEqual(finding.waived, accepted)
                self.assertEqual(quality_gate(findings, audit)["result"], "PASS" if accepted else "FAIL")


if __name__ == "__main__":
    unittest.main()
