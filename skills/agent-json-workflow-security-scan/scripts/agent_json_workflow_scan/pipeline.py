from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any
import json
import uuid

import yaml
from jsonschema import Draft202012Validator

from .advisory import merge_model_advisory
from .cluster import build_test_cluster
from .engine import execute_rules
from .models import PRODUCER_VERSION, SCHEMA_VERSION, Finding, WorkflowIR, to_jsonable, utc_now, write_json
from .parser import parse_workflow
from .report import attack_surface, attack_surface_markdown, dynamic_plan, report_json, report_markdown, semantic_inventory


def artifact(payload: dict[str, Any], scan_id: str, producer: str, workflow_hash: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "scan_id": scan_id,
        "producer": producer,
        "producer_version": PRODUCER_VERSION,
        "workflow_hash": workflow_hash,
        "created_at": utc_now(),
        **payload,
    }


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
        if waiver.get("workflow_hash") not in (None, "", workflow_hash):
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
    result = "FAIL" if blockers else "REVIEW" if reviews else "PASS"
    return {"result": result, "blocker_ids": blockers, "review_ids": reviews, "coverage_gap_ids": coverage_gaps, "waiver_audit": waiver_audit}


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


def write_index(output: Path, scan_id: str, workflow_hash: str) -> None:
    entries = []
    for path in sorted(output.iterdir()):
        if not path.is_file() or path.name == "12-artifact-index.json":
            continue
        content = path.read_bytes()
        entries.append({"file": path.name, "size": len(content), "sha256": sha256(content).hexdigest()})
    write_json(output / "12-artifact-index.json", artifact({"artifacts": entries}, scan_id, "artifact-indexer", workflow_hash))


def run_scan(*, dsl_path: Path, output_dir: Path, rules_path: Path, samples_path: Path | None = None, waivers_path: Path | None = None, model_advisory_path: Path | None = None, mode: str = "assessment") -> dict[str, Any]:
    if mode not in {"assessment", "structure-only"}:
        raise ValueError("mode must be assessment or structure-only")
    output_dir.mkdir(parents=True, exist_ok=True)
    ir, _document = parse_workflow(dsl_path)
    samples = load_samples(samples_path)
    validate_samples(samples, ir, mode)
    scan_id = str(uuid.uuid4())
    manifest = {"mode": mode, "source_file": dsl_path.name, "source_shape": ir.source_shape, "rules_file": rules_path.name, "samples_confirmed": samples.get("confirmed_by_user") is True, "model_advisory_supplied": model_advisory_path is not None}
    write_json(output_dir / "00-scan-manifest.json", artifact({"manifest": manifest}, scan_id, "scan-orchestrator", ir.workflow_hash))
    write_json(output_dir / "01-workflow-ir.json", artifact({"workflow_ir": ir}, scan_id, "json-workflow-parser", ir.workflow_hash))
    facts, findings, candidates = execute_rules(ir, rules_path)
    write_json(output_dir / "02-security-facts.json", artifact({"facts": facts}, scan_id, "deterministic-rule-engine", ir.workflow_hash))
    inventory = semantic_inventory(ir, findings)
    write_json(output_dir / "03-semantic-inventory.json", artifact({"semantic_inventory": inventory}, scan_id, inventory["producer"], ir.workflow_hash))
    write_json(output_dir / "04-rule-candidates.json", artifact({"rule_candidates": candidates}, scan_id, "deterministic-rule-engine", ir.workflow_hash))
    base_tests = build_test_cluster(samples, findings, ir)
    tests, model_advisory = merge_model_advisory(model_advisory_path, ir, findings, samples, base_tests)
    write_json(output_dir / "05-test-cluster.json", artifact({"test_cluster": tests}, scan_id, tests["producer"], ir.workflow_hash))
    write_json(output_dir / "06-model-advisory.json", artifact({"model_advisory": model_advisory}, scan_id, "model-boundary", ir.workflow_hash))
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
    write_json(output_dir / "07-verification.json", artifact({"verification": verification}, scan_id, "deterministic-verifier", ir.workflow_hash))
    if not verification["passed"]:
        raise ValueError(f"Artifact verification failed: {verification}")
    write_json(output_dir / "08-findings.json", artifact({"findings": findings}, scan_id, "deterministic-rule-engine", ir.workflow_hash))
    surface = attack_surface(ir, findings, tests, inventory)
    write_json(output_dir / "09-attack-surface.json", artifact({"attack_surface": surface}, scan_id, "attack-surface-builder", ir.workflow_hash))
    (output_dir / "attack-surface.md").write_text(attack_surface_markdown(surface), encoding="utf-8")
    write_json(output_dir / "10-dynamic-test-plan.json", artifact({"dynamic_test_plan": dynamic_plan(surface, tests)}, scan_id, "sandbox-plan-builder", ir.workflow_hash))
    write_json(output_dir / "11-quality-gate.json", artifact({"quality_gate": gate}, scan_id, "quality-gate", ir.workflow_hash))
    report = report_json(ir, findings, gate, tests, surface, model_advisory)
    write_json(output_dir / "report.json", artifact({"report": report}, scan_id, "report-builder", ir.workflow_hash))
    (output_dir / "report.md").write_text(report_markdown(to_jsonable(report)), encoding="utf-8")
    write_index(output_dir, scan_id, ir.workflow_hash)
    risk_count = sum(item.report_group == "risk" for item in findings)
    return {"scan_id": scan_id, "workflow_hash": ir.workflow_hash, "quality_gate": gate["result"], "finding_count": risk_count, "total_record_count": len(findings), "output_dir": str(output_dir), "exit_code": 1 if gate["result"] == "FAIL" else 0}
