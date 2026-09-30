#!/usr/bin/env python
"""CLI: plan §9 validation checklist -- run before any result from this program is
believed. Checks what can be checked mechanically; items needing a live BOR-BOX are
flagged as not runnable in this environment.

Usage:
    python scripts/run_validate.py --run-dir reports/run1 \
        --secondary-normal reports/graphtunnel_normal.json \
        --secondary-wildcard reports/graphtunnel_wildcard.json
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def check(label: str, ok: bool, detail: str = "") -> bool:
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {label}" + (f" -- {detail}" if detail else ""))
    return ok


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path, help="Output dir from run_pipeline.py")
    parser.add_argument("--tp-smoke-min-rate", type=float, default=0.5,
                         help="Minimum fraction of labeled exfil rows expected to trip R1 or R4 (default 0.5)")
    parser.add_argument("--secondary-normal", type=Path, default=None)
    parser.add_argument("--secondary-wildcard", type=Path, default=None)
    args = parser.parse_args()

    all_ok = True

    pipeline_result = json.loads((args.run_dir / "pipeline_result.json").read_text(encoding="utf-8"))

    # 1. TP smoke test (§9.1)
    labeled = pipeline_result["accounting"]["labeled"]
    r1_rate = pipeline_result["tp_rule_hit_rate"].get("R1", 0.0)
    r4_rate = pipeline_result["tp_rule_hit_rate"].get("R4", 0.0)
    tp_ok = labeled > 0 and max(r1_rate, r4_rate) >= args.tp_smoke_min_rate
    all_ok &= check(
        "TP smoke test (labeled exfil rows trip R1/R4)", tp_ok,
        f"labeled={labeled}, R1 rate={r1_rate:.1%}, R4 rate={r4_rate:.1%}",
    )

    # 2. Zero-suspicion rule (§9.2)
    zero_rules = [
        rid for rid, agg in pipeline_result["independent_aggregates"].items()
        if agg["match_count"] == 0
    ]
    all_ok &= check(
        "Zero-suspicion rule (no rule silently matches 0 records)", not zero_rules,
        f"zero-match rules: {zero_rules}" if zero_rules else "",
    )

    # 3. Golden tests green (§6.3) -- Python-side only; BOR-BOX-engine comparison is not
    # runnable in this environment (no live box / Docker testbed here).
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_golden_rules.py", "tests/test_engine_parity.py", "-q"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    golden_ok = proc.returncode == 0
    all_ok &= check("Golden tests green (harness side)", golden_ok, proc.stdout.strip().splitlines()[-1] if proc.stdout else "")
    print("  NOTE: BOR-BOX-engine-side golden comparison (plan §6.3, via Scapy/Docker testbed) "
          "is not runnable in this environment and must be done separately against the real box.")

    # 4. Row accounting (§9.4)
    all_ok &= check("Row accounting (reader = quarantined + labeled + benign)",
                     pipeline_result["accounting_check_ok"])

    # 5. Secondary-corpus cross-check (§9.5)
    if args.secondary_normal or args.secondary_wildcard:
        for tag, path in (("normal", args.secondary_normal), ("wildcard", args.secondary_wildcard)):
            if path is None:
                continue
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            print(f"[INFO] secondary corpus ({tag}): {data['total_records']} records, "
                  f"per-rule fp_pct={ {k: v['fp_pct'] for k, v in data['per_rule'].items()} }")
    else:
        print("[SKIP] secondary-corpus cross-check not provided (--secondary-normal/--secondary-wildcard)")

    print()
    print("OVERALL:", "PASS" if all_ok else "FAIL -- do not treat results as authoritative until fixed")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
