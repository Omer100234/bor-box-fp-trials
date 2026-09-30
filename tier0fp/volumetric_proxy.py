"""Volumetric QPS Flood proxy pass -- catalog §1.

The catalog's real designated rule for this attack is a deployment-specific exact-QNAME
whitelist for one protected zone (`IF QNAME IS www.example.com ALLOW ... IF QNAME IS
*.example.com LIMIT`) -- not a generic content signature, so unlike R1-R6 it can't be
evaluated against arbitrary QNAMEs the way this project measures the other rules.

This is a different, queue-based generalization of the same defensive idea, per request:
instead of a static per-zone whitelist, keep a sliding one-second *queue of the most recent
packets seen for each registrable domain (2LD)* and flag a record when its own zone's
trailing-window rate crosses a threshold -- the generic "is this zone currently being
flooded" signal a real volumetric rate-limiter would use. Swept across several thresholds
(there is no single "right" number in the catalog, unlike R7's plan-specified 100ms/500ms/1s)
because the whole point is to see where the FP curve bends from "normal traffic concentration"
into "attack-scale".

Same streaming/ordering assumption as r7_proxy.py: records arrive in non-decreasing timestamp
order (true of the source ISP log). Memory is bounded the same way R7's is -- a per-2LD queue
only holds entries within the trailing WINDOW_SECONDS, and a global recency FIFO evicts 2LD
dict entries that have gone untouched for longer than that, so memory tracks the number of
distinct 2LDs active in the trailing window (at real query rates, a few hundred to low
thousands), not the number of distinct 2LDs ever seen across the whole run.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Tuple

WINDOW_SECONDS = 1.0
# Queries/sec to a single registrable domain within the trailing 1s window. Whole-corpus
# average is on the order of tens to hundreds of req/s spread across tens of thousands of
# distinct 2LDs (plan §5 diurnal profile: ~209K-2.5M req/hour corpus-wide), so anything a
# single 2LD sustains in double digits is already a real concentration; the catalog's own
# attack description ("thousands of queries per second" against one zone) sits far above the
# top of this sweep, deliberately, so the curve shows where FPs start well before attack scale.
THRESHOLDS = (5, 10, 20, 50, 100, 250, 500, 1000)


@dataclass
class VolumetricQPSProxyState:
    total_benign: int = 0
    flag_count: Dict[int, int] = field(default_factory=lambda: {t: 0 for t in THRESHOLDS})
    max_rate_seen: int = 0
    _queues: Dict[str, Deque[float]] = field(default_factory=dict)
    _global_recency: Deque[Tuple[float, str]] = field(default_factory=deque)

    def observe(self, twoLD: str, ts: float) -> int:
        """Record one benign packet for `twoLD` at `ts`; returns its zone's instantaneous
        trailing-1s rate (including this packet) -- the "queue length" a real rate-limiter
        reading this same sliding window would see."""
        self.total_benign += 1
        q = self._queues.get(twoLD)
        if q is None:
            q = deque()
            self._queues[twoLD] = q
        q.append(ts)
        cutoff = ts - WINDOW_SECONDS
        while q and q[0] < cutoff:
            q.popleft()

        rate = len(q)
        if rate > self.max_rate_seen:
            self.max_rate_seen = rate
        for threshold in THRESHOLDS:
            if rate >= threshold:
                self.flag_count[threshold] += 1

        self._global_recency.append((ts, twoLD))
        while self._global_recency and self._global_recency[0][0] < cutoff:
            _old_ts, old_2ld = self._global_recency.popleft()
            oq = self._queues.get(old_2ld)
            if oq is not None:
                # This 2LD may not have been observed again since its own front-eviction
                # last ran (that only happens inside its own observe() call above), so
                # prune it against the current cutoff here too before deciding it's stale.
                while oq and oq[0] < cutoff:
                    oq.popleft()
                if not oq:
                    del self._queues[old_2ld]

        return rate

    def to_summary(self) -> dict:
        return {
            "total_benign": self.total_benign,
            "window_seconds": WINDOW_SECONDS,
            "max_single_2ld_rate_seen": self.max_rate_seen,
            "thresholds": {
                str(t): {
                    "flagged_count": self.flag_count[t],
                    "fraction": (self.flag_count[t] / self.total_benign) if self.total_benign else 0.0,
                }
                for t in THRESHOLDS
            },
            "label": (
                "queue-based generalization of the catalog's per-zone whitelist rule "
                "(catalog §1), not a measurement of the real deployed rule -- see module "
                "docstring"
            ),
        }
