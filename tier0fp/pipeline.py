"""Single streaming pass, plan §7. Nothing loads the full corpus into memory: the reader
yields rows one at a time and every stage below is a generator/accumulator over that stream.
"""
from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from .aggregate import RuleAggregate, approx_registrable_domain
from .canonicalize import canonicalize_qname
from .r7_proxy import R7ProxyState
from .rules import (
    ATTACK_GROUPS,
    INDEPENDENT_RULES,
    R5_ALLOW_RULES,
    SYSTEM_ORDER,
    evaluate_attack_groups,
    evaluate_independent,
    evaluate_system,
)
from .schema import SchemaConfig


@dataclass
class RowAccounting:
    reader_rows: int = 0
    quarantined: int = 0
    labeled: int = 0
    benign: int = 0

    def check(self) -> bool:
        """Plan §9.4: reader rows = quarantined + labeled + benign, exact equality."""
        return self.reader_rows == (self.quarantined + self.labeled + self.benign)


# Threshold to detect a millisecond-epoch timestamp masquerading as seconds: real
# unix-seconds values stay below this for tens of thousands of years, while unix-ms values
# for any real-world date are comfortably above it. Confirmed necessary and correct against
# the actual Mendeley dataset.csv: dataset_description.txt does not document the unit, but
# every raw timestamp there is 13-digit milliseconds (e.g. 1624438272607) -- treating it as
# seconds without this conversion inflates the corpus's apparent span from the plan's
# documented ~26 hours to ~3 years and silently breaks R7's Delta-t burst comparisons and
# the per-hour aggregation buckets. dataset_modified.csv, by contrast, already uses
# 10-digit unix-seconds timestamps and is unaffected by this conversion.
_MS_EPOCH_THRESHOLD = 1e12


def _parse_ts(raw: str) -> Optional[float]:
    raw = (raw or "").strip()
    if raw == "":
        return None
    try:
        value = float(raw)
        if value > _MS_EPOCH_THRESHOLD:
            value /= 1000.0
        return value
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    return None


def read_rows(csv_path: Path, schema: SchemaConfig) -> Iterator[list]:
    with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f, delimiter=schema.delimiter)
        if schema.has_header:
            next(reader, None)
        for row in reader:
            yield row


@dataclass
class PipelineResult:
    accounting: RowAccounting
    independent_aggregates: dict
    attack_group_aggregates: dict
    system_allow_count: int
    system_no_match_count: int
    r7: R7ProxyState
    malformed_examples: list
    quarantine_dir: Path
    tp_dir: Path
    tp_rule_hit_counts: dict
    tp_attack_group_hit_counts: dict


def run_pipeline(
    csv_path: Path,
    schema: SchemaConfig,
    output_dir: Path,
    max_malformed_examples: int = 20,
    progress_every: int = 1_000_000,
) -> PipelineResult:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    quarantine_path = output_dir / "quarantined_rows.csv"
    tp_path = output_dir / "labeled_rows.csv"

    accounting = RowAccounting()
    aggregates = {rule.id: RuleAggregate(rule.id) for rule in INDEPENDENT_RULES}
    # Per-attack union aggregates (bor-box-attack-rule-catalog.md): "does ANY rule
    # belonging to this attack's designated rule set match", not summed per-rule counts
    # (which would double-count records matching more than one rule in the same group).
    attack_aggregates = {name: RuleAggregate(name) for name in ATTACK_GROUPS}
    system_allow_count = 0
    system_no_match_count = 0
    r7 = R7ProxyState()
    malformed_examples = []
    # §9.1 TP smoke test: independent-rule hit counts on the labeled (malicious) rows,
    # tracked separately from the benign FP aggregates -- these never count toward any FP
    # rate, they only prove the harness/normalization isn't silently broken.
    tp_rule_hit_counts = {rule.id: 0 for rule in INDEPENDENT_RULES}
    tp_attack_group_hit_counts = {name: 0 for name in ATTACK_GROUPS}

    start = time.time()

    with open(quarantine_path, "w", encoding="utf-8", newline="") as qf, open(
        tp_path, "w", encoding="utf-8", newline=""
    ) as tf:
        qwriter = csv.writer(qf)
        twriter = csv.writer(tf)
        qwriter.writerow(["raw_row", "reason"])
        twriter.writerow(["client", "ts", "qname_raw", "qname_canonical", "label"])

        for row in read_rows(csv_path, schema):
            accounting.reader_rows += 1

            try:
                client = row[schema.client_col]
                ts_raw = row[schema.ts_col]
                qname_raw = row[schema.qname_col]
                label_raw = row[schema.label_col]
            except IndexError:
                accounting.quarantined += 1
                qwriter.writerow([row, "column_index_out_of_range"])
                if len(malformed_examples) < max_malformed_examples:
                    malformed_examples.append({"row": row, "reason": "column_index_out_of_range"})
                continue

            canon = canonicalize_qname(qname_raw)
            ts = _parse_ts(ts_raw)

            if canon.is_malformed or ts is None:
                accounting.quarantined += 1
                reason = "malformed_qname" if canon.is_malformed else "unparseable_timestamp"
                qwriter.writerow([row, reason])
                if len(malformed_examples) < max_malformed_examples:
                    malformed_examples.append({"row": row, "reason": reason})
                continue

            if not schema.is_benign_label(label_raw):
                accounting.labeled += 1
                twriter.writerow([client, ts_raw, qname_raw, canon.normalized, label_raw])
                tp_indep = evaluate_independent(canon.normalized)
                for rule_id, matched in tp_indep.items():
                    if matched:
                        tp_rule_hit_counts[rule_id] += 1
                for name, hit in evaluate_attack_groups(canon.normalized, tp_indep).items():
                    if hit["independent"]:
                        tp_attack_group_hit_counts[name] += 1
                continue

            accounting.benign += 1
            qname = canon.normalized

            indep = evaluate_independent(qname)
            twoLD = approx_registrable_domain(qname)
            hour_bucket = int(ts // 3600)
            for rule_id, matched in indep.items():
                if matched:
                    aggregates[rule_id].record_independent(qname, client, hour_bucket, twoLD)

            group_hits = evaluate_attack_groups(qname, indep)
            for name, hit in group_hits.items():
                if hit["independent"]:
                    attack_aggregates[name].record_independent(qname, client, hour_bucket, twoLD)
                if hit["system"]:
                    attack_aggregates[name].record_system_win()

            system_outcome = evaluate_system(qname)
            if system_outcome == "R5_ALLOW":
                system_allow_count += 1
            elif system_outcome is None:
                system_no_match_count += 1
            else:
                aggregates[system_outcome].record_system_win()

            r7.observe(client, qname, ts)

            if progress_every and accounting.reader_rows % progress_every == 0:
                elapsed = time.time() - start
                print(f"[pipeline] {accounting.reader_rows:,} rows in {elapsed:.1f}s", flush=True)

    result = PipelineResult(
        accounting=accounting,
        independent_aggregates={rid: agg.to_summary() for rid, agg in aggregates.items()},
        attack_group_aggregates={name: agg.to_summary() for name, agg in attack_aggregates.items()},
        system_allow_count=system_allow_count,
        system_no_match_count=system_no_match_count,
        r7=r7,
        malformed_examples=malformed_examples,
        quarantine_dir=quarantine_path,
        tp_dir=tp_path,
        tp_rule_hit_counts=tp_rule_hit_counts,
        tp_attack_group_hit_counts=tp_attack_group_hit_counts,
    )

    (output_dir / "pipeline_result.json").write_text(
        json.dumps(
            {
                "accounting": accounting.__dict__,
                "accounting_check_ok": accounting.check(),
                "independent_aggregates": result.independent_aggregates,
                "attack_group_aggregates": result.attack_group_aggregates,
                "system_allow_count": system_allow_count,
                "system_no_match_count": system_no_match_count,
                "r7_proxy": r7.to_summary(),
                "malformed_examples": malformed_examples,
                "tp_rule_hit_counts": tp_rule_hit_counts,
                "tp_rule_hit_rate": {
                    rid: (count / accounting.labeled if accounting.labeled else 0.0)
                    for rid, count in tp_rule_hit_counts.items()
                },
                "tp_attack_group_hit_counts": tp_attack_group_hit_counts,
                "tp_attack_group_hit_rate": {
                    name: (count / accounting.labeled if accounting.labeled else 0.0)
                    for name, count in tp_attack_group_hit_counts.items()
                },
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    return result
