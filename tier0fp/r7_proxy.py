"""R7 (TsuNAME/Kaminsky similarity) proxy pass -- plan §3/§7.

R7's real predicate is "IF IN HEADER EXACT EXCEPT txid LIMIT", which needs response/header
bytes this dataset does not have. The proxy: per (client, qname), a sub-second repeat is
approximated as a same-client/same-QNAME record arriving within Delta-t of the previous
record for that same key. Swept at 100ms / 500ms / 1s per plan §7.

Implementation note (disclosed, not silently corrected, per the §8 ethos): this is a single
streaming pass assuming records arrive in non-decreasing timestamp order (true of the
source ISP log). A record is flagged "in-burst" at threshold Δt if the gap to the previous
record sharing its (client, qname) key is <= Δt. This flags only the trailing record of each
pair, not the leading one, so it is a slight undercount of "records inside a burst" -- output
remains labeled as an upper-bound proxy for the rule's true (header-based) FP contribution,
per plan §7/§10.5, not as an exact burst-membership count.

Memory note: an earlier version kept one dict entry per distinct (client, qname) pair for
the entire run. On the real ~35M-row / 35,989-client / 691,303-unique-QNAME corpus that grew
into millions of entries and OOM-killed the process. Since no threshold here exceeds
MAX_THRESHOLD_SECONDS, a key that has gone untouched for longer than that can never
contribute to a future match, so it's evicted -- bounding memory to roughly the number of
distinct keys active within the trailing MAX_THRESHOLD_SECONDS window (a few thousand at
real query rates), not the number of distinct keys ever seen.
"""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Tuple


THRESHOLDS_SECONDS = (0.1, 0.5, 1.0)
MAX_THRESHOLD_SECONDS = max(THRESHOLDS_SECONDS)


@dataclass
class R7ProxyState:
    total_benign: int = 0
    burst_count: Dict[float, int] = field(default_factory=lambda: {t: 0 for t in THRESHOLDS_SECONDS})
    _last_ts: Dict[Tuple[str, str], float] = field(default_factory=dict)
    _eviction_queue: Deque[Tuple[float, Tuple[str, str]]] = field(default_factory=deque)

    def observe(self, client: str, canonical_qname: str, ts: float) -> None:
        self.total_benign += 1
        key = (client, canonical_qname)
        last = self._last_ts.get(key)
        if last is not None:
            gap = ts - last
            if gap >= 0:
                for threshold in THRESHOLDS_SECONDS:
                    if gap <= threshold:
                        self.burst_count[threshold] += 1
        self._last_ts[key] = ts
        self._eviction_queue.append((ts, key))
        self._evict(ts)

    def _evict(self, current_ts: float) -> None:
        cutoff = current_ts - MAX_THRESHOLD_SECONDS
        queue = self._eviction_queue
        last_ts = self._last_ts
        while queue and queue[0][0] < cutoff:
            old_ts, old_key = queue.popleft()
            # Only delete if nothing re-touched this key since this queue entry was
            # made (i.e. this is still the most recent record for the key) -- otherwise
            # the live, newer entry would be deleted out from under it.
            if last_ts.get(old_key) == old_ts:
                del last_ts[old_key]

    def to_summary(self) -> dict:
        return {
            "total_benign": self.total_benign,
            "thresholds": {
                str(t): {
                    "in_burst_count": self.burst_count[t],
                    "fraction": (self.burst_count[t] / self.total_benign) if self.total_benign else 0.0,
                }
                for t in THRESHOLDS_SECONDS
            },
            "label": "upper-bound proxy, not a direct measurement of R7 (plan §3/§7)",
        }


# --- R7QueueProxyState: count-based "K of last N" variant -------------------------------
#
# Per request, an alternative to the Δt-burst proxy above that mirrors the catalog's own
# description of R7 more literally: "similarity rule over the last K packets" (catalog §7),
# not a time-window -- so this tracks a fixed-size queue of the most recent WINDOW_SIZE
# packets and fires when at least THRESHOLD of them share the same signature.
#
# Scope decision (documented, not hidden): the real rule is "HEADER EXACT EXCEPT txid" --
# every DNS header field and the question section must match except the 16-bit transaction
# ID, which has nothing to do with which client sent it. A middlebox evaluating this reads
# one global packet stream (bor-box-attack-rule-catalog.md Appendix B: "the C layer parsing
# packets and maintaining history buffers"), not a per-client one. So this proxy's window is
# GLOBAL across all clients, keyed only on canonical QNAME (our only available stand-in for
# "header except txid", same limitation as the Δt proxy above) -- unlike R7ProxyState, which
# is scoped per (client, qname) for a different reason (that one approximates "the client
# re-asked", this one approximates "the box's recent packet stream looks repetitive").
WINDOW_SIZE = 100
REPEAT_THRESHOLD = 5


@dataclass
class R7QueueProxyState:
    window_size: int = WINDOW_SIZE
    threshold: int = REPEAT_THRESHOLD
    total_benign: int = 0
    flagged_count: int = 0
    _window: Deque[str] = field(default_factory=deque)
    _counts: Counter = field(default_factory=Counter)

    def observe(self, canonical_qname: str) -> bool:
        """Push one packet's QNAME into the trailing window; returns True if, counting this
        packet itself, at least `threshold` of the last `window_size` packets share it."""
        self.total_benign += 1
        window = self._window
        counts = self._counts

        if len(window) >= self.window_size:
            oldest = window.popleft()
            counts[oldest] -= 1
            if counts[oldest] <= 0:
                del counts[oldest]

        window.append(canonical_qname)
        counts[canonical_qname] += 1

        flagged = counts[canonical_qname] >= self.threshold
        if flagged:
            self.flagged_count += 1
        return flagged

    def to_summary(self) -> dict:
        return {
            "total_benign": self.total_benign,
            "window_size": self.window_size,
            "threshold": self.threshold,
            "flagged_count": self.flagged_count,
            "fraction": (self.flagged_count / self.total_benign) if self.total_benign else 0.0,
            "label": (
                f"queue-based proxy ({self.threshold} of last {self.window_size} packets "
                "sharing the same QNAME, global across clients) for R7's 'HEADER EXACT "
                "EXCEPT txid' similarity rule -- QNAME-only stand-in, not a direct "
                "measurement; see module docstring for scope"
            ),
        }
