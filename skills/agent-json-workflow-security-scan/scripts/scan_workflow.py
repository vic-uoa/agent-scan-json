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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Deterministic static scanner for the internal JSON workflow DSL.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--dsl", type=Path, required=True)
    scan.add_argument("--samples", type=Path)
    scan.add_argument("--output", type=Path, required=True)
    scan.add_argument("--mode", choices=("assessment", "structure-only"), default="assessment")
    scan.add_argument("--rules", type=Path, default=SCRIPT_DIR.parent / "rules" / "core-rules.yml")
    scan.add_argument("--waivers", type=Path)
    scan.add_argument("--model-advisory", type=Path, help="Optional non-authoritative model proposals JSON; never changes findings or gate.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        result = run_scan(
            dsl_path=args.dsl, samples_path=args.samples, output_dir=args.output,
            rules_path=args.rules, waivers_path=args.waivers, model_advisory_path=args.model_advisory, mode=args.mode,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return int(result["exit_code"])
    except Exception as error:
        print(json.dumps({"error": str(error), "type": type(error).__name__}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
