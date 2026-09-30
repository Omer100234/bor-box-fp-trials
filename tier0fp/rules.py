"""Tier-0 rule definitions (plan §3) and evaluation semantics (plan §5).

Each rule specifies its own match mode (fullmatch vs search) per plan §6.2: the DFA path
in the box does anchored full-scan matching, Python distinguishes match/search/fullmatch,
and R3 is unanchored at the end, so it must use search semantics while R1/R2/R4 use
fullmatch. This is encoded per-rule here, not left to convention.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class Rule:
    id: str
    source_slide: str
    description: str
    pattern: str
    mode: str  # "fullmatch" or "search"
    action: str  # "LIMIT" or "ALLOW"
    flags: int = 0

    def __post_init__(self):
        object.__setattr__(self, "_compiled", re.compile(self.pattern, self.flags))

    @property
    def compiled(self) -> re.Pattern:
        return self._compiled  # type: ignore[attr-defined]

    def matches(self, qname: str) -> bool:
        if self.mode == "fullmatch":
            return self.compiled.fullmatch(qname) is not None
        elif self.mode == "search":
            return self.compiled.search(qname) is not None
        raise ValueError(f"unknown mode {self.mode!r} on rule {self.id}")


# --- R1-R4, R6: QNAME-only Tier-0 rules under test -------------------------------------

# R1 uses a possessive quantifier ({8,}+). Python's re supports it from 3.11+; this
# project pins Python >=3.11 (see engine_parity.py for the equivalence check against the
# non-possessive variant, run as part of the golden-test suite per plan §6.1).
R1 = Rule(
    id="R1",
    source_slide="Water torture — Takeuchi rule 1",
    description="High-entropy long single label, exactly 3 remaining labels",
    pattern=r"^[a-zA-Z0-9]{8,}+\.[^.]+\.[^.]+\.$",
    mode="fullmatch",
    action="LIMIT",
)

# Non-possessive variant of R1, used only for the engine-parity equivalence assertion
# (plan §6.1) -- must never be used for actual measurement, only to prove the possessive
# and non-possessive forms produce identical match sets on anchored patterns like this one.
R1_NONPOSSESSIVE = Rule(
    id="R1_NONPOSSESSIVE",
    source_slide="Water torture — Takeuchi rule 1 (parity check variant)",
    description="Same as R1 without the possessive quantifier",
    pattern=r"^[a-zA-Z0-9]{8,}\.[^.]+\.[^.]+\.$",
    mode="fullmatch",
    action="LIMIT",
)

R2 = Rule(
    id="R2",
    source_slide="Water torture — Takeuchi rule 2",
    description="5+ labels deep (water-torture style long subdomain chains)",
    pattern=r"^([^.]+\.){4,}[^.]+\.[^.]+\.$",
    mode="fullmatch",
    action="LIMIT",
)

# R3 is unanchored at the end per plan §6.2 -- search semantics required.
R3 = Rule(
    id="R3",
    source_slide="Water torture — Takeuchi rule 3",
    description="Mixed digit/letter/digit pattern anywhere before a label boundary",
    pattern=r"^[^.]*[0-9][^.]*[a-z][^.]*[0-9][^.]*\.",
    mode="search",
    action="LIMIT",
)

R4 = Rule(
    id="R4",
    source_slide='"Important Notes" simplified variant',
    description="High-entropy long first label, at least 2 remaining labels",
    pattern=r"^[a-zA-Z0-9]{8,}\..+\.$",
    mode="fullmatch",
    action="LIMIT",
)

R6 = Rule(
    id="R6",
    source_slide="TuDoor — QNAME condition only",
    description="Empty label anywhere in the QNAME (consecutive dots)",
    pattern=r"(\.\.+)",
    mode="search",
    action="LIMIT",
)

INDEPENDENT_RULES = (R1, R2, R3, R4, R6)

# --- R5: CDN/cloud ALLOW list ------------------------------------------------------------
#
# ASSUMPTION / TODO: the plan references an "11 rules" ALLOW list from the source slides
# but only shows 2 entries verbatim (cloudfront.net, azurefd.net). The other 9 below are a
# reasonable placeholder built from common CDN/cloud edge-node suffixes and are NOT taken
# from the original slide deck -- replace ALLOWLIST_DOMAINS with the actual 11-entry list
# before treating R5/system-mode numbers as authoritative. Independent-mode R1-R4/R6
# numbers are unaffected by this placeholder.
ALLOWLIST_DOMAINS = [
    r"\.cloudfront\.net\.$",
    r"\.azurefd\.net\.$",
    r"\.akamaiedge\.net\.$",
    r"\.akamaitechnologies\.com\.$",
    r"\.edgekey\.net\.$",
    r"\.edgesuite\.net\.$",
    r"\.fastly\.net\.$",
    r"\.cloudflare\.net\.$",
    r"\.googleusercontent\.com\.$",
    r"\.amazonaws\.com\.$",
    r"\.googleapis\.com\.$",
]
assert len(ALLOWLIST_DOMAINS) == 11, "R5 ALLOW list must have 11 entries per plan §3"

R5_ALLOW_RULES = tuple(
    Rule(
        id=f"R5.{i + 1}",
        source_slide="CDN/cloud ALLOW list (11 rules)",
        description=f"ALLOW list entry: {pat}",
        pattern=pat,
        mode="search",
        action="ALLOW",
    )
    for i, pat in enumerate(ALLOWLIST_DOMAINS)
)

# --- R7: TsuNAME / Kaminsky similarity ----------------------------------------------------
# Cannot be evaluated from this dataset directly (no header/txid). Implemented separately
# in r7_proxy.py as a same-client/same-QNAME sub-second repeat-burst proxy, per plan §3/§7.


def evaluate_independent(qname: str, rules=INDEPENDENT_RULES) -> dict:
    """Plan §5 independent mode: every rule evaluated against the record in isolation."""
    return {rule.id: rule.matches(qname) for rule in rules}


# System-mode deployment order: R5 ALLOW list first (first-match-wins within the list is
# irrelevant to the outcome since they all ALLOW), then R1-R4/R6 in configured order.
SYSTEM_ORDER = (R1, R2, R3, R4, R6)


def is_allowed(qname: str, allow_rules=R5_ALLOW_RULES) -> bool:
    return any(rule.matches(qname) for rule in allow_rules)


def evaluate_system(qname: str, allow_rules=R5_ALLOW_RULES, ordered_rules=SYSTEM_ORDER) -> Optional[str]:
    """Plan §5 system mode: first-match-wins across ALLOW list then R1-R4/R6.

    Returns the id of the first matching rule (action LIMIT), or "R5_ALLOW" if an ALLOW
    entry matched first, or None if nothing matched (default pass-through).
    """
    if is_allowed(qname, allow_rules):
        return "R5_ALLOW"
    for rule in ordered_rules:
        if rule.matches(qname):
            return rule.id
    return None


# --- Attack groups (bor-box-attack-rule-catalog.md) --------------------------------------
#
# Per the catalog's own cross-reference (Appendix A) and per-attack sections, rules group by
# attack as follows for the query-only (QNAME + per-client timing) subset this program can
# measure:
#   - Water Torture (catalog §2): R1, R2, R3, R4 (the "simplified variant") are its
#     designated rules; the CDN/cloud ALLOW list (R5) is explicitly scoped in the catalog as
#     "FP suppression companion to the water-torture rules" -- NOT a universal pre-filter for
#     every attack. So the ALLOW list only gates the Water Torture group here.
#   - TuDoor (catalog §8): its designated rule is
#     "QR=1 AND (QDCOUNT=0 OR QDCOUNT>1 OR QNAME~(\.\.+)) LIMIT" -- only the QNAME sub-clause
#     (R6) is testable from a QNAME-only dataset, and moreover the QR=1 condition can never
#     be true on this dataset at all (these are client-facing *request* records, never
#     responses), so the fully-gated real rule would structurally never fire here regardless
#     of R6's result. R6 alone is reported as the best available proxy for the QNAME clause,
#     ungated by the water-torture ALLOW list (the catalog doesn't scope that list to TuDoor).
#   - TsuNAME (catalog §7) and Cache Poisoning (catalog §12) both use the
#     "HEADER EXACT EXCEPT txid" similarity mechanism, which needs response/txid data this
#     dataset doesn't have -- see r7_proxy.py for the same-client/same-QNAME approximation
#     used for TsuNAME specifically; Cache Poisoning's variant additionally requires QR=1
#     (a response), so it cannot even be approximated from request-only data.
#   - Volumetric QPS Flood (catalog §1) and every response/header-only attack (catalog
#     §3-6, §9-11) have no representation here at all -- not included below.
ATTACK_GROUPS = {
    "water_torture": ("R1", "R2", "R3", "R4"),
    "tudoor_qname_only": ("R6",),
}


def evaluate_attack_groups(qname: str, indep: Optional[dict] = None) -> dict:
    """Per-attack union match: does ANY rule belonging to this attack's designated rule set
    match? Independent = ignoring any ALLOW list; system = after applying the Water-Torture
    ALLOW list (which, per the catalog, only gates the water_torture group)."""
    if indep is None:
        indep = evaluate_independent(qname)
    allowed = is_allowed(qname)
    result = {}
    for attack, rule_ids in ATTACK_GROUPS.items():
        indep_hit = any(indep[rid] for rid in rule_ids)
        if attack == "water_torture":
            system_hit = indep_hit and not allowed
        else:
            system_hit = indep_hit
        result[attack] = {"independent": indep_hit, "system": system_hit}
    return result
