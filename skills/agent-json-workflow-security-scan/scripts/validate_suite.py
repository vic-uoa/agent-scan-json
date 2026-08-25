#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import argparse
import json
import sys


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from agent_json_workflow_scan.pipeline import run_scan  # noqa: E402


CASES = [
    {"name": "safe-workflow", "gate": "PASS", "max_findings": 0},
    {"name": "risky-workflow", "gate": "FAIL", "required": {"FLOW-009", "LLM-003", "TOOL-005"}},
    {"name": "contract-workflow", "gate": "REVIEW", "required": {"FLOW-007", "FLOW-012", "TOOL-008"}},
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    root = SCRIPT_DIR.parent
    results = []
    for case in CASES:
        output = args.output / case["name"]
        run = run_scan(
            dsl_path=root / "tests" / "fixtures" / f"{case['name']}.json",
            output_dir=output,
            rules_path=root / "rules" / "core-rules.yml",
            mode="structure-only",
        )
        report = json.loads((output / "report.json").read_text(encoding="utf-8"))["report"]
        rule_ids = {rule for item in report["findings"] for rule in [item["rule_id"], *item.get("related_rule_ids", [])]}
        required = case.get("required", set())
        count_ok = report["summary"]["finding_count"] <= case.get("max_findings", 1000)
        passed = run["quality_gate"] == case["gate"] and required.issubset(rule_ids) and count_ok
        results.append({"case": case["name"], "gate": run["quality_gate"], "finding_count": report["summary"]["finding_count"], "missing_rules": sorted(required - rule_ids), "passed": passed})
    summary = {"suite": "internal-json-workflow-security", "passed": all(item["passed"] for item in results), "cases": results}
    (args.output / "validation-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
