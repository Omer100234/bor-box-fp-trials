"""Aggregation primitives for pipeline stage 5 (plan §7): per-rule counts, per-2LD top-K,
per-client counts, hourly counts, and a fixed-seed reservoir sample of matching QNAMEs.
"""
from __future__ import annotations

import heapq
import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List


def approx_registrable_domain(canonical_qname: str) -> str:
    """Naive last-two-labels approximation of a registrable domain (2LD).

    NOT public-suffix-list aware: "example.co.uk." will be reported as "co.uk" rather than
    "example.co.uk". This is a documented approximation (plan does not mandate a PSL
    dependency); treat 2LD attribution tables as directional, not exact, for multi-part
    TLDs. Good enough for CDN/DNSBL/ad-tech 2LD attribution, which is what §10.2 asks for.
    """
    labels = [l for l in canonical_qname.split(".") if l != ""]
    if len(labels) < 2:
        return canonical_qname
    return ".".join(labels[-2:])


class ReservoirSampler:
    """Fixed-size, fixed-seed reservoir sample (Algorithm R) for reproducible runs
    (plan §7 determinism requirement)."""

    def __init__(self, k: int, seed: int):
        self.k = k
        self._rng = random.Random(seed)
        self._sample: List[str] = []
        self._seen = 0

    def offer(self, item: str) -> None:
        self._seen += 1
        if len(self._sample) < self.k:
            self._sample.append(item)
        else:
            j = self._rng.randint(0, self._seen - 1)
            if j < self.k:
                self._sample[j] = item

    @property
    def sample(self) -> List[str]:
        return list(self._sample)


class TopKTracker:
    """Maintains exact counts (Counter) and exposes a top-K view via a heap at read time."""

    def __init__(self):
        self._counts: Counter = Counter()

    def add(self, key: str) -> None:
        self._counts[key] += 1

    def top_k(self, k: int) -> List[tuple]:
        return heapq.nlargest(k, self._counts.items(), key=lambda kv: kv[1])

    @property
    def counts(self) -> Counter:
        return self._counts


@dataclass
class RuleAggregate:
    rule_id: str
    match_count: int = 0
    system_match_count: int = 0  # matches that also "win" in system mode (post-ALLOW residual)
    per_2ld: TopKTracker = field(default_factory=TopKTracker)
    per_client: TopKTracker = field(default_factory=TopKTracker)
    per_hour: Counter = field(default_factory=Counter)
    reservoir: ReservoirSampler = field(default_factory=lambda: ReservoirSampler(k=200, seed=1337))

    def record_independent(self, qname: str, client: str, hour_bucket: int, twoLD: str) -> None:
        self.match_count += 1
        self.per_2ld.add(twoLD)
        self.per_client.add(client)
        self.per_hour[hour_bucket] += 1
        self.reservoir.offer(qname)

    def record_system_win(self) -> None:
        self.system_match_count += 1

    def to_summary(self, top_k: int = 20) -> dict:
        return {
            "rule_id": self.rule_id,
            "match_count": self.match_count,
            "system_match_count": self.system_match_count,
            "top_2ld": self.per_2ld.top_k(top_k),
            "top_clients": self.per_client.top_k(top_k),
            "per_hour": dict(sorted(self.per_hour.items())),
            "exemplar_sample": self.reservoir.sample,
        }
