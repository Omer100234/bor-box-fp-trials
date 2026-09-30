"""Plan §9.5: cross-check R1-R4/R6 on the GraphTunnel normal/ and wildcard/ sets.

Format assumption (undocumented in the plan -- adjust if the actual GraphTunnel export
differs): each of normal/ and wildcard/ is a directory tree of text files, one QNAME per
line, no header. Every non-blank line across every file under the directory is treated as
one record; there is no per-record client/timestamp/label in this cross-check, only the
QNAME rules R1-R4/R6, matching what §9.5 asks for (rates, not attribution tables).
"""
from __future__ import annotations

import json
from pathlib import Path

from .canonicalize import canonicalize_qname
from .rules import INDEPENDENT_RULES, evaluate_independent


def _iter_qnames(root: Path):
    for path in sorted(Path(root).rglob("*")):
        if not path.is_file():
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield line


def run_secondary_corpus(root: Path, label: str) -> dict:
    total = 0
    malformed = 0
    match_counts = {rule.id: 0 for rule in INDEPENDENT_RULES}

    for raw in _iter_qnames(root):
        canon = canonicalize_qname(raw)
        if canon.is_malformed:
            malformed += 1
            continue
        total += 1
        for rule_id, matched in evaluate_independent(canon.normalized).items():
            if matched:
                match_counts[rule_id] += 1

    return {
        "label": label,
        "root": str(root),
        "total_records": total,
        "malformed_skipped": malformed,
        "per_rule": {
            rule_id: {
                "match_count": count,
                "fp_pct": round((count / total * 100), 4) if total else 0.0,
            }
            for rule_id, count in match_counts.items()
        },
    }


def compare_to_primary(secondary_result: dict, primary_report: dict) -> dict:
    """Plan §9.5: divergence direction and magnitude go in the report as external
    validity evidence."""
    primary_by_rule = {row["rule_id"]: row["independent_fp_pct"] for row in primary_report["per_rule_results"]}
    comparison = {}
    for rule_id, stats in secondary_result["per_rule"].items():
        primary_pct = primary_by_rule.get(rule_id, 0.0)
        comparison[rule_id] = {
            "primary_isp_fp_pct": primary_pct,
            "secondary_fp_pct": stats["fp_pct"],
            "delta_pct_points": round(stats["fp_pct"] - primary_pct, 4),
        }
    return comparison


def write_secondary_report(root: Path, label: str, primary_report_path: Path | None, output_path: Path) -> dict:
    result = run_secondary_corpus(root, label)
    if primary_report_path is not None:
        primary_report = json.loads(Path(primary_report_path).read_text(encoding="utf-8"))
        result["comparison_to_primary"] = compare_to_primary(result, primary_report)
    Path(output_path).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
