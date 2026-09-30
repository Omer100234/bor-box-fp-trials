"""Dataset profile (plan §4.5): the sanity anchor run before any rule executes. Single
streaming pass; only bounded state is kept (a Counter of 2LDs and hour buckets can grow
large but is proportional to distinct values, not row count).
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .aggregate import approx_registrable_domain
from .canonicalize import canonicalize_qname
from .pipeline import _parse_ts, read_rows
from .schema import SchemaConfig


@dataclass
class DatasetProfile:
    record_count: int = 0
    unique_qnames: set = field(default_factory=set)
    unique_clients: set = field(default_factory=set)
    label_counts: Counter = field(default_factory=Counter)
    twoLD_counts: Counter = field(default_factory=Counter)
    records_per_hour: Counter = field(default_factory=Counter)
    punycode_count: int = 0
    malformed_count: int = 0
    min_ts: float = float("inf")
    max_ts: float = float("-inf")

    def to_summary(self, top_k: int = 30) -> dict:
        return {
            "record_count": self.record_count,
            "unique_qname_count": len(self.unique_qnames),
            "unique_client_count": len(self.unique_clients),
            "label_counts": dict(self.label_counts.most_common(50)),
            "top_2ld": self.twoLD_counts.most_common(top_k),
            "records_per_hour": dict(sorted(self.records_per_hour.items())),
            "punycode_count": self.punycode_count,
            "malformed_count": self.malformed_count,
            "time_span_seconds": (self.max_ts - self.min_ts) if self.record_count else None,
        }


def build_profile(csv_path: Path, schema: SchemaConfig, output_path: Path | None = None) -> DatasetProfile:
    profile = DatasetProfile()

    for row in read_rows(csv_path, schema):
        try:
            client = row[schema.client_col]
            ts_raw = row[schema.ts_col]
            qname_raw = row[schema.qname_col]
            label_raw = row[schema.label_col]
        except IndexError:
            profile.malformed_count += 1
            continue

        canon = canonicalize_qname(qname_raw)
        if canon.is_malformed:
            profile.malformed_count += 1
            continue
        profile.record_count += 1
        if canon.is_punycode:
            profile.punycode_count += 1

        profile.unique_qnames.add(canon.normalized)
        profile.unique_clients.add(client)
        profile.label_counts[(label_raw or "").strip().lower() or "<blank>"] += 1
        profile.twoLD_counts[approx_registrable_domain(canon.normalized)] += 1

        ts = _parse_ts(ts_raw)
        if ts is not None:
            profile.min_ts = min(profile.min_ts, ts)
            profile.max_ts = max(profile.max_ts, ts)
            profile.records_per_hour[int(ts // 3600)] += 1

    if output_path:
        Path(output_path).write_text(json.dumps(profile.to_summary(), indent=2, default=str), encoding="utf-8")

    return profile
