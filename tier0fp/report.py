"""Stage 6 report rendering (plan §9 outputs): per-rule table, attribution tables, ALLOW-list
candidates, and the mandatory limitations section.
"""
from __future__ import annotations

import json
from pathlib import Path

REFERENCE_QPS = (10_000, 50_000)


def _fp_row(key: str, match_count: int, system_match_count: int, benign_total: int, key_field: str = "rule_id") -> dict:
    fp_rate = (match_count / benign_total) if benign_total else 0.0
    system_rate = (system_match_count / benign_total) if benign_total else 0.0
    return {
        key_field: key,
        "independent_fp_pct": round(fp_rate * 100, 4),
        "independent_fp_per_million": round(fp_rate * 1_000_000, 1),
        "system_fp_pct": round(system_rate * 100, 4),
        "system_fp_per_million": round(system_rate * 1_000_000, 1),
        "projected_false_limit_per_sec": {
            str(qps): round(system_rate * qps, 3) for qps in REFERENCE_QPS
        },
    }


def render_report(pipeline_result_path: Path, output_path: Path) -> dict:
    data = json.loads(Path(pipeline_result_path).read_text(encoding="utf-8"))
    accounting = data["accounting"]
    benign_total = accounting["benign"]

    per_rule_table = []
    allow_list_candidates_2ld = {}
    for rule_id, agg in data["independent_aggregates"].items():
        per_rule_table.append(
            _fp_row(rule_id, agg["match_count"], agg["system_match_count"], benign_total)
        )
        for twoLD, count in agg["top_2ld"]:
            allow_list_candidates_2ld[twoLD] = allow_list_candidates_2ld.get(twoLD, 0) + count

    allow_candidates_ranked = sorted(allow_list_candidates_2ld.items(), key=lambda kv: -kv[1])[:50]

    attack_group_table = [
        _fp_row(name, agg["match_count"], agg["system_match_count"], benign_total, key_field="attack")
        for name, agg in data.get("attack_group_aggregates", {}).items()
    ]

    report = {
        "accounting": accounting,
        "accounting_check_ok": data["accounting_check_ok"],
        "per_rule_results": per_rule_table,
        "per_attack_results": attack_group_table,
        "attack_group_attribution": {
            name: {
                "top_2ld": agg["top_2ld"],
                "top_clients": agg["top_clients"],
                "per_hour": agg["per_hour"],
                "rules_in_group": {"water_torture": ["R1", "R2", "R3", "R4"], "tudoor_qname_only": ["R6"]}.get(name, []),
            }
            for name, agg in data.get("attack_group_aggregates", {}).items()
        },
        "system_allow_count": data["system_allow_count"],
        "system_no_match_count": data["system_no_match_count"],
        "attribution": {
            rule_id: {
                "top_2ld": agg["top_2ld"],
                "top_clients": agg["top_clients"],
                "per_hour": agg["per_hour"],
            }
            for rule_id, agg in data["independent_aggregates"].items()
        },
        "exemplar_appendix": {
            rule_id: agg["exemplar_sample"] for rule_id, agg in data["independent_aggregates"].items()
        },
        "allow_list_candidates_ranked": allow_candidates_ranked,
        "r7_proxy": data["r7_proxy"],
        "limitations": [
            "Query-side (QNAME + per-client timing) rules only; response-side rules "
            "(NXNS/NRDelegation, CacheFlush ANCOUNT/NSCOUNT, KeyTrap, NSEC3 iterations, "
            "RRSet bloating, TuDoor QDCOUNT, SIG(0)) are out of scope and measured by the "
            "separate re-resolution harness.",
            "Single ISP, single ~26-hour window, dataset-era name mix -- not a claim of "
            "general external validity beyond the secondary-corpus cross-check in §9.5.",
            "R7 is reported as an upper-bound proxy (same-client/same-QNAME sub-second "
            "repeat bursts), not a direct measurement of the header-based TsuNAME rule.",
            "Ground truth is benign-by-absence-of-label: unlabeled traffic is assumed "
            "benign per plan §8; any unlabeled malicious traffic in the corpus would "
            "deflate (not inflate) the reported FP rates.",
            "The R5 CDN/cloud ALLOW list used here is a documented placeholder "
            "(tier0fp/rules.py: ALLOWLIST_DOMAINS) standing in for the actual 11-entry "
            "list from the source slides -- system-mode/residual numbers should be "
            "re-run once the real list is substituted.",
        ],
    }

    Path(output_path).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return report


def render_markdown_summary(report: dict, output_path: Path) -> None:
    lines = ["# BOR-BOX Tier-0 False-Positive Measurement — Results", ""]
    lines.append(f"Benign population (N): {report['accounting']['benign']:,}")
    lines.append(f"Row accounting check: {'OK' if report['accounting_check_ok'] else 'FAILED'}")
    lines.append("")
    lines.append("## Per-attack results (rules grouped by designated attack)")
    lines.append("")
    lines.append("| Attack | Indep FP% | Indep FP/M | System FP% | System FP/M | @10k qps | @50k qps |")
    lines.append("|---|---|---|---|---|---|---|")
    for row in report.get("per_attack_results", []):
        lines.append(
            f"| {row['attack']} | {row['independent_fp_pct']} | {row['independent_fp_per_million']} "
            f"| {row['system_fp_pct']} | {row['system_fp_per_million']} "
            f"| {row['projected_false_limit_per_sec']['10000']} "
            f"| {row['projected_false_limit_per_sec']['50000']} |"
        )
    lines.append("")
    lines.append("## Per-rule results")
    lines.append("")
    lines.append("| Rule | Indep FP% | Indep FP/M | System FP% | System FP/M | @10k qps | @50k qps |")
    lines.append("|---|---|---|---|---|---|---|")
    for row in report["per_rule_results"]:
        lines.append(
            f"| {row['rule_id']} | {row['independent_fp_pct']} | {row['independent_fp_per_million']} "
            f"| {row['system_fp_pct']} | {row['system_fp_per_million']} "
            f"| {row['projected_false_limit_per_sec']['10000']} "
            f"| {row['projected_false_limit_per_sec']['50000']} |"
        )
    lines.append("")
    lines.append(f"System ALLOW hits: {report['system_allow_count']:,}")
    lines.append(f"System no-match (pass-through): {report['system_no_match_count']:,}")
    lines.append("")
    lines.append("## R7 proxy (upper bound)")
    for threshold, stats in report["r7_proxy"]["thresholds"].items():
        lines.append(f"- Δt={threshold}s: {stats['in_burst_count']:,} ({stats['fraction']*100:.4f}%)")
    lines.append("")
    lines.append("## Limitations")
    for item in report["limitations"]:
        lines.append(f"- {item}")

    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
