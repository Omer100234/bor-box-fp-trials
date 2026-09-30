#!/usr/bin/env python
"""CLI: full streaming pipeline (plan §7) + report rendering (plan §9/§10).

Usage:
    python scripts/run_pipeline.py --csv data/raw/dataset.csv --schema config/schema.json \
        --out reports/run1
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tier0fp.pipeline import run_pipeline
from tier0fp.report import render_markdown_summary, render_report
from tier0fp.schema import SchemaConfig


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--schema", required=True, type=Path, help="Path to a SchemaConfig JSON file")
    parser.add_argument("--out", required=True, type=Path, help="Output directory for this run")
    args = parser.parse_args()

    schema = SchemaConfig.from_json(args.schema)
    result = run_pipeline(args.csv, schema, args.out)

    print(f"Row accounting OK: {result.accounting.check()}  ({result.accounting})")
    for rule_id, hits in result.tp_rule_hit_counts.items():
        rate = hits / result.accounting.labeled if result.accounting.labeled else 0.0
        print(f"TP smoke test  {rule_id}: {hits}/{result.accounting.labeled} labeled rows hit ({rate:.1%})")
    for rule_id, agg in result.independent_aggregates.items():
        if agg["match_count"] == 0:
            print(f"ZERO-SUSPICION: {rule_id} matched 0 of {result.accounting.benign} benign records -- "
                  f"investigate before celebrating (plan §9.2, likely trailing-dot/anchoring bug).")

    report = render_report(args.out / "pipeline_result.json", args.out / "report.json")
    render_markdown_summary(report, args.out / "report.md")
    print(f"\nReport written to {args.out / 'report.json'} and {args.out / 'report.md'}")


if __name__ == "__main__":
    main()
