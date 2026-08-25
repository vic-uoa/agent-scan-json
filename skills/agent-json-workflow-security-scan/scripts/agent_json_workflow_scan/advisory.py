from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any
import json
import re

from jsonschema import Draft202012Validator

from .cluster import canonical, route_plan
from .models import Finding, WorkflowIR


SECRET_VALUE_RE = re.compile(r"(?i)(?:bearer\s+[A-Za-z0-9._~+/=-]{12,}|sk-(?:proj-)?[A-Za-z0-9_-]{16,}|-----BEGIN(?: RSA| EC| OPENSSH)? PRIVATE KEY-----)")


def _contains_secret(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_secret(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    return isinstance(value, str) and bool(SECRET_VALUE_RE.search(value))


def merge_model_advisory(path: Path | None, ir: WorkflowIR, findings: list[Finding], samples: dict[str, Any], base: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    boundary = {
        "enabled": path is not None,
        "authoritative": False,
        "allowed_uses": ["additional_inert_test_proposals", "non_authoritative_report_wording", "coverage_gap_review_questions"],
        "forbidden_uses": ["create_or_delete_findings", "change_status_severity_or_confidence", "change_quality_gate", "claim_execution"],
        "accepted_case_ids": [],
        "rejected": [],
        "executive_summary": None,
        "priority_actions": [],
        "review_questions": [],
    }
    if path is None:
        boundary["reason"] = "No model advisory file supplied; deterministic scan remains complete within its declared scope."
        return base, boundary
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    schema_path = Path(__file__).resolve().parents[2] / "schemas" / "model-advisory.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda item: list(item.absolute_path))
    if errors:
        first = errors[0]
        location = "/" + "/".join(str(item) for item in first.absolute_path)
        raise ValueError(f"Model advisory schema violation at {location or '/'}: {first.message}")
    boundary["generated_by"] = payload["generated_by"]
    finding_ids = {item.id for item in findings}
    finding_map = {item.id: item for item in findings}
    node_ids = {item.id for item in ir.nodes}
    seed_ids = {str(item.get("sample_id") or f"SEED-{index + 1:03d}") for index, item in enumerate(samples.get("samples", [])) if isinstance(item, dict)}
    allowed_rule_ids = {rule for item in findings for rule in [item.rule_id, *item.related_rule_ids]}
    boundary["executive_summary"] = payload.get("executive_summary")
    for action in payload.get("priority_actions", []):
        invalid = sorted(set(action["finding_ids"]) - finding_ids)
        if invalid:
            boundary["rejected"].append({"kind": "priority_action", "reason": "unknown_finding_ids", "refs": invalid})
        else:
            boundary["priority_actions"].append(action)
    for question in payload.get("review_questions", []):
        invalid = sorted(set(question["node_ids"]) - node_ids)
        if invalid:
            boundary["rejected"].append({"kind": "review_question", "reason": "unknown_node_ids", "refs": invalid})
        else:
            boundary["review_questions"].append(question)
    merged = deepcopy(base)
    existing_case_ids = {str(item.get("case_id")) for item in merged.get("cases", [])}
    existing_inputs = {canonical(item.get("input", {})) for item in merged.get("cases", []) if isinstance(item, dict)}
    for case in payload.get("cases", []):
        reasons = []
        if case["case_id"] in existing_case_ids:
            reasons.append("duplicate_case_id")
        if set(case["seed_sample_ids"]) - seed_ids:
            reasons.append("unknown_seed_sample_id")
        if set(case["finding_ids"]) - finding_ids:
            reasons.append("unknown_finding_id")
        if set(case["target_nodes"]) - node_ids:
            reasons.append("unknown_target_node")
        if set(case.get("rule_ids", [])) - allowed_rule_ids:
            reasons.append("unknown_rule_id")
        if _contains_secret(case["input"]):
            reasons.append("possible_real_secret")
        encoded = canonical(case["input"])
        if encoded in existing_inputs:
            reasons.append("duplicate_concrete_input")
        for finding_id in case["finding_ids"]:
            expected_targets = set(finding_map[finding_id].node_ids)
            if not expected_targets.intersection(case["target_nodes"]):
                reasons.append("finding_target_mismatch")
        if reasons:
            boundary["rejected"].append({"kind": "test_case", "case_id": case["case_id"], "reason": sorted(set(reasons))})
            continue
        proposal = deepcopy(case)
        target = case["target_nodes"][0]
        route = route_plan(ir, target)
        proposal.update({
            "generation_source": "model_proposal",
            "case_type": "negative",
            "mutated_paths": [],
            "route_status": route["status"],
            "route_constraints": route["constraints"],
            "missing_route_context": route["missing_context"],
            "oracle": {"assertion_mode": "model_proposal", "must_reach_target": target, "expected_route_nodes": route["path"], "forbidden_effects": case["forbidden_effects"]},
        })
        merged.setdefault("cases", []).append(proposal)
        existing_case_ids.add(case["case_id"])
        existing_inputs.add(encoded)
        boundary["accepted_case_ids"].append(case["case_id"])
    audit = merged.setdefault("generation_audit", {})
    audit["model_proposed_count"] = len(boundary["accepted_case_ids"])
    audit["model_rejected_count"] = sum(item.get("kind") == "test_case" for item in boundary["rejected"])
    audit["all_cases_not_executed"] = all(item.get("execution_status") == "NOT_EXECUTED" for item in merged.get("cases", []))
    audit["unique_input_count"] = len({canonical(item.get("input", {})) for item in merged.get("cases", [])})
    if boundary["accepted_case_ids"]:
        merged["producer"] = "deterministic-plus-validated-model-proposals"
    return merged, boundary
