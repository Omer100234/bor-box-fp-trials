"""Response-side rule evaluators (bor-box-attack-rule-catalog.md §3-§6, §10, §11).

Each function is a pure predicate over already-extracted wire-format fields -- true record
counts within RRsets (not dnspython's RRset-group counts; see live_harness.py's
`count_records`), matching exactly what the catalog's rule syntax reads. Kept separate from
live_harness.py so the rule logic itself is unit-testable without any network access.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ReferralCapture:
    """One referral hop (QR=1, AA=0) seen during an iterative root->TLD->authoritative walk."""
    qr: bool
    aa: bool
    nscount: int
    arcount: int
    hop: str  # e.g. "root->tld", "tld->auth"
    domain: str


@dataclass(frozen=True)
class FinalAnswerCapture:
    """A final (non-referral) answer response, QR=1."""
    qr: bool
    ancount: int
    domain: str


@dataclass(frozen=True)
class KeyTrapCapture:
    dnskey_count: int
    rrsig_count_on_dnskey: int
    ds_count: int
    domain: str


@dataclass(frozen=True)
class Nsec3Capture:
    iterations: Optional[int]  # None if the zone doesn't use NSEC3 (e.g. plain NSEC, or unsigned)
    domain: str


def nxns_nrdelegation(r: ReferralCapture) -> bool:
    """Catalog §3: QR=1 AND AA=0 AND NSCOUNT>10 AND ARCOUNT<10."""
    return r.qr and (not r.aa) and r.nscount > 10 and r.arcount < 10


def cacheflush_cname(f: FinalAnswerCapture) -> bool:
    """Catalog §4: QR=1 AND ANCOUNT>9."""
    return f.qr and f.ancount > 9


def cacheflush_ns_referral(r: ReferralCapture) -> bool:
    """Catalog §5: QR=1 AND NSCOUNT>13."""
    return r.qr and r.nscount > 13


def rrset_bloating(r: ReferralCapture) -> bool:
    """Catalog §11: QR=1 AND (NS>50 OR AR>50). Uses the same referral captures as §3/§5,
    since a referral's authority(NS)/additional(AR) sections are exactly what this rule
    reads -- the catalog's shape is a superset check applied to the same packets."""
    return r.qr and (r.nscount > 50 or r.arcount > 50)


def keytrap_dnskey(k: KeyTrapCapture) -> bool:
    """Catalog §6 (SigJam/KeySigTrap): DNSKEY count > 10."""
    return k.dnskey_count > 10


def keytrap_rrsig(k: KeyTrapCapture) -> bool:
    """Catalog §6 (LockCram): RRSIG count (covering the DNSKEY RRset) > 10."""
    return k.rrsig_count_on_dnskey > 10


def keytrap_ds(k: KeyTrapCapture) -> bool:
    """Catalog §6 (HashTrap): DS record count > 10."""
    return k.ds_count > 10


def nsec3_iterations(n: Nsec3Capture) -> bool:
    """Catalog §10: NSEC3 iterations >= 11 (the regex matches 11+). Not applicable (returns
    False, and should be excluded from the applicable-population denominator by the caller)
    if the zone doesn't use NSEC3 at all."""
    return n.iterations is not None and n.iterations >= 11
