from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
from typing import Any
import json
import uuid

import yaml
from jsonschema import Draft202012Validator

from .advisory import merge_model_advisory
from .cluster import build_test_cluster
from .engine import execute_rules
from .models import Finding, WorkflowIR, to_jsonable
from .parser import parse_workflow
from .report import attack_surface, render_html_report, report_json, semantic_inventory


def load_samples(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"confirmed_by_user": False, "samples": []}
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict) or not isinstance(payload.get("samples"), list):
        raise ValueError("Samples must be an object containing a samples array")
    schema_path = Path(__file__).resolve().parents[2] / "schemas" / "samples.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda item: list(item.absolute_path))
    if errors:
        first = errors[0]
        location = "/" + "/".join(str(item) for item in first.absolute_path)
        raise ValueError(f"Samples schema violation at {location or '/'}: {first.message}")
    return payload


def validate_samples(samples: dict[str, Any], ir: WorkflowIR, mode: str) -> None:
    if mode == "structure-only":
        return
    if samples.get("confirmed_by_user") is not True:
        raise ValueError("assessment mode requires confirmed_by_user=true after explicit user confirmation")
    if samples.get("confirmed_dsl_sha256") != ir.workflow_hash:
        raise ValueError("confirmed_dsl_sha256 does not match the current DSL")
    if not samples.get("samples"):
        raise ValueError("assessment mode requires at least one representative sample")
    for index, sample in enumerate(samples["samples"]):
        if not isinstance(sample, dict) or not isinstance(sample.get("input"), dict) or not sample["input"]:
            raise ValueError(f"sample {index} must contain a non-empty input object")
        if not sample.get("expected_business_intent") and not sample.get("expected_security_invariants"):
            raise ValueError(f"sample {index} requires expected_business_intent or expected_security_invariants")


def load_waivers(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"waivers": []}
    text = path.read_text(encoding="utf-8-sig")
    payload = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    return payload if isinstance(payload, dict) else {"waivers": []}


def apply_waivers(findings: list[Finding], payload: dict[str, Any], workflow_hash: str) -> dict[str, Any]:
    applied, rejected = [], []
    for waiver in payload.get("waivers", []) if isinstance(payload.get("waivers"), list) else []:
        if not isinstance(waiver, dict):
            continue
        waiver_id = str(waiver.get("id") or "")
        finding_id = str(waiver.get("finding_id") or "")
        valid = bool(waiver_id and finding_id and waiver.get("approver") and waiver.get("justification") and waiver.get("expires_at"))
        if waiver.get("workflow_hash") != workflow_hash:
            valid = False
        try:
            expires_at = datetime.fromisoformat(str(waiver.get("expires_at") or "").replace("Z", "+00:00"))
            valid = valid and expires_at.tzinfo is not None and expires_at > datetime.now(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            valid = False
        finding = next((item for item in findings if item.id == finding_id), None)
        if valid and finding:
            finding.waived = True
            finding.waiver_id = waiver_id
            applied.append(waiver_id)
        else:
            rejected.append(waiver_id or finding_id or "unnamed")
    return {"applied": applied, "rejected": rejected}


def quality_gate(findings: list[Finding], waiver_audit: dict[str, Any]) -> dict[str, Any]:
    risk_findings = [item for item in findings if item.report_group == "risk"]
    blockers = [item.id for item in risk_findings if not item.waived and item.status == "CONFIRMED" and item.severity in {"CRITICAL", "HIGH"}]
    reviews = [item.id for item in risk_findings if not item.waived and item.status in {"CONFIRMED", "OBSERVED", "PROBABLE", "CANDIDATE"}]
    coverage_gaps = [item.id for item in findings if not item.waived and item.report_group == "coverage_gap"]
    scanner_gap_ids = [
        item.id for item in findings
        if not item.waived and item.report_group == "coverage_gap"
        and {item.rule_id, *item.related_rule_ids}.intersection({"FLOW-002", "FLOW-003", "TOOL-011"})
    ]
    runtime_gap_ids = [item for item in coverage_gaps if item not in scanner_gap_ids]
    result = "FAIL" if blockers else "REVIEW" if reviews else "PASS"
    completeness_result = "INCOMPLETE" if scanner_gap_ids else "RUNTIME_EVIDENCE_REQUIRED" if runtime_gap_ids else "COMPLETE"
    return {
        "result": result,
        "risk_gate_result": result,
        "completeness_result": completeness_result,
        "blocker_ids": blockers,
        "review_ids": reviews,
        "coverage_gap_ids": coverage_gaps,
        "scanner_gap_ids": scanner_gap_ids,
        "runtime_gap_ids": runtime_gap_ids,
        "waiver_audit": waiver_audit,
    }


def verify(findings: list[Finding], facts: list[Any], candidates: dict[str, Any], tests: dict[str, Any], ir: WorkflowIR) -> dict[str, Any]:
    node_ids = {node.id for node in ir.nodes}
    fact_ids = {fact.id for fact in facts}
    finding_ids = {item.id for item in findings}
    raw_rule_ids = {item["rule_id"] for item in candidates.get("raw_matches", [])}
    aggregate_rule_ids = {rule_id for item in findings for rule_id in [item.rule_id, *item.related_rule_ids]}
    invalid_nodes = sorted({node_id for item in findings for node_id in item.node_ids if node_id not in node_ids})
    invalid_facts = sorted({fact_id for item in findings for fact_id in item.evidence_refs if fact_id not in fact_ids})
    invalid_test_refs = sorted({finding_id for case in tests.get("cases", []) for finding_id in case.get("finding_ids", []) if finding_id not in finding_ids})
    lost_rules = sorted(raw_rule_ids - aggregate_rule_ids)
    all_not_executed = all(case.get("execution_status") == "NOT_EXECUTED" for case in tests.get("cases", []))
    passed = not invalid_nodes and not invalid_facts and not invalid_test_refs and not lost_rules and all_not_executed
    return {"passed": passed, "invalid_node_refs": invalid_nodes, "invalid_fact_refs": invalid_facts, "invalid_test_finding_refs": invalid_test_refs, "lost_raw_rule_ids": lost_rules, "all_tests_not_executed": all_not_executed}


def run_scan(*, dsl_path: Path, output_dir: Path, rules_path: Path, samples_path: Path | None = None, waivers_path: Path | None = None, model_advisory_path: Path | None = None, mode: str = "assessment") -> dict[str, Any]:
    if mode not in {"assessment", "structure-only"}:
        raise ValueError("mode must be assessment or structure-only")
    ir, _document = parse_workflow(dsl_path)
    samples = load_samples(samples_path)
    validate_samples(samples, ir, mode)
    scan_id = str(uuid.uuid4())
    facts, findings, candidates = execute_rules(ir, rules_path)
    inventory = semantic_inventory(ir, findings)
    base_tests = build_test_cluster(samples, findings, ir)
    tests, model_advisory = merge_model_advisory(model_advisory_path, ir, findings, samples, base_tests)
    waiver_audit = apply_waivers(findings, load_waivers(waivers_path), ir.workflow_hash)
    gate = quality_gate(findings, waiver_audit)
    verification = verify(findings, facts, candidates, tests, ir)
    verification["authority_boundary"] = {
        "finding_status_severity_confidence_are_deterministic": True,
        "model_advisory_can_modify_findings": False,
        "model_advisory_can_modify_quality_gate": False,
        "accepted_model_cases_remain_not_executed": all(
            case.get("execution_status") == "NOT_EXECUTED"
            for case in tests.get("cases", [])
            if case.get("generation_source") == "model_proposal"
        ),
    }
    if not verification["passed"]:
        raise ValueError(f"Artifact verification failed: {verification}")
    surface = attack_surface(ir, findings, tests, inventory)
    report = report_json(ir, findings, gate, tests, surface, model_advisory)
    report_dir = output_dir / _report_directory_name(dsl_path)
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"{_report_directory_name(dsl_path)}-安全扫描报告.html"
    report_path.write_text(render_html_report(to_jsonable(report)), encoding="utf-8")
    risk_count = sum(item.report_group == "risk" for item in findings)
    return {
        "scan_id": scan_id,
        "workflow_hash": ir.workflow_hash,
        "quality_gate": gate["result"],
        "risk_gate": gate["risk_gate_result"],
        "completeness_result": gate["completeness_result"],
        "scanner_gap_count": len(gate["scanner_gap_ids"]),
        "runtime_gap_count": len(gate["runtime_gap_ids"]),
        "finding_count": risk_count,
        "total_record_count": len(findings),
        "output_dir": str(report_dir.resolve()),
        "report_path": str(report_path.resolve()),
        "exit_code": 1 if gate["result"] == "FAIL" else 0,
        "_verification": verification,
        "_test_cluster": tests,
        "_model_advisory": model_advisory,
        "_findings": findings,
        "_report": report,
    }


def _report_directory_name(dsl_path: Path) -> str:
    """Use the uploaded workflow filename while preserving a valid Windows path."""
    invalid = '<>:"/\\|?*\x00'
    safe = "".join("_" if char in invalid or ord(char) < 32 else char for char in dsl_path.stem)
    return safe.rstrip(". ") or "workflow"
