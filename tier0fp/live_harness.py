"""Live re-resolution harness (bor-box-attack-rule-catalog.md §3-§6, §10, §11).

The original measurement plan scoped response-side rules out, deferring them to "a separate
re-resolution harness that replays this dataset's name distribution live and captures
wire-format responses." This is that harness: it takes a sample of REAL domain names (drawn
from this project's own corpus -- genuine legitimate ISP traffic -- plus a small curated
supplement for DNSSEC/NSEC3 diversity) and issues real DNS queries against real production
infrastructure (the actual root servers, and a public recursive resolver), capturing genuine
wire-format responses. The response-side rules are then applied to that real, legitimate
traffic to measure their false-positive rate -- no synthetic data anywhere in this module.

Politeness: modest sample size, small per-query delay, short timeouts, single retry. Root
server queries alone are a negligible fraction of what any single consumer resolver already
generates; there is no volumetric intent here.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import List, Optional

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from .response_rules import (
    FinalAnswerCapture,
    KeyTrapCapture,
    Nsec3Capture,
    ReferralCapture,
    cacheflush_cname,
    cacheflush_ns_referral,
    keytrap_dnskey,
    keytrap_ds,
    keytrap_rrsig,
    nsec3_iterations,
    nxns_nrdelegation,
    rrset_bloating,
)

ROOT_SERVERS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10",
    "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
    "193.0.14.129", "199.7.83.42", "202.12.27.33",
]

PUBLIC_RESOLVERS = ["8.8.8.8", "1.1.1.1"]

# Curated supplement: real, long-established production domains added specifically for
# DNSSEC/NSEC3 diversity, since the corpus's own top-2LD list (mega-platforms) skews toward
# domains that may not represent typical signed-zone shapes. None of these are synthetic.
DNSSEC_DIVERSITY_SUPPLEMENT = [
    "paypal.com", "verisign.com", "cloudflare.com", "github.com", "isc.org",
    "ripe.net", "icann.org", "nist.gov", "sec.gov", "comcast.net",
    "att.com", "ibm.com", "cisco.com", "digicert.com", "godaddy.com",
]

# Corpus-derived entries that aren't resolvable domain names at all (mDNS link-local noise,
# or a 2LD-extraction artifact that captured a stray port suffix) -- excluded, not measured.
_NOT_REAL_DOMAINS = {"local.local", "ddns.net:8080", "ddns.net"}


def count_records(rrset_list) -> int:
    """True wire-format record count: dnspython groups same-name/same-type records into one
    RRset object, so len(section) undercounts -- must sum len(rrset) per rrset."""
    return sum(len(rrset) for rrset in rrset_list)


def clean_domain_list(raw_2lds: List[str]) -> List[str]:
    return [d for d in raw_2lds if d not in _NOT_REAL_DOMAINS and ":" not in d]


def build_sample_domains(corpus_2lds: List[str]) -> List[str]:
    combined = clean_domain_list(corpus_2lds) + DNSSEC_DIVERSITY_SUPPLEMENT
    seen = set()
    out = []
    for d in combined:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _next_hop_ip(response: dns.message.Message, resolver: dns.resolver.Resolver) -> Optional[str]:
    for rrset in response.additional:
        if rrset.rdtype == dns.rdatatype.A:
            return str(rrset[0])
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            ns_name = str(rrset[0].target)
            try:
                ans = resolver.resolve(ns_name, "A", lifetime=4)
                return str(ans[0])
            except Exception:
                return None
    return None


def walk_referrals(domain: str, fallback_resolver: dns.resolver.Resolver, timeout: float = 4.0, max_hops: int = 3) -> List[ReferralCapture]:
    """Iterative walk from a root server, capturing every referral (QR=1, AA=0) hop seen
    before a final answer or failure. This is the only way to observe genuine referral
    packets -- a normal recursive-resolver query only ever returns the final answer, never
    the intermediate referrals a resolver like BOR-BOX actually processes."""
    hops: List[ReferralCapture] = []
    qname = domain if domain.endswith(".") else domain + "."
    ip = random.choice(ROOT_SERVERS)
    hop_label = "root->tld"

    for _ in range(max_hops):
        q = dns.message.make_query(qname, dns.rdatatype.A)
        try:
            resp = dns.query.udp(q, ip, timeout=timeout)
        except Exception:
            break

        if resp.answer or not resp.authority:
            break

        qr = bool(resp.flags & dns.flags.QR)
        aa = bool(resp.flags & dns.flags.AA)
        nscount = count_records(resp.authority)
        arcount = count_records(resp.additional)
        hops.append(ReferralCapture(qr=qr, aa=aa, nscount=nscount, arcount=arcount, hop=hop_label, domain=domain))

        next_ip = _next_hop_ip(resp, fallback_resolver)
        if not next_ip:
            break
        ip = next_ip
        hop_label = "deeper"

    return hops


def capture_final_answer(domain: str, resolver: dns.resolver.Resolver) -> Optional[FinalAnswerCapture]:
    try:
        ans = resolver.resolve(domain, "A", lifetime=5)
        ancount = count_records(ans.response.answer)
        return FinalAnswerCapture(qr=True, ancount=ancount, domain=domain)
    except Exception:
        return None


def capture_keytrap(domain: str, resolver: dns.resolver.Resolver) -> Optional[KeyTrapCapture]:
    dnskey_count = 0
    rrsig_count = 0
    ds_count = 0
    got_any = False

    try:
        q = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
        resp = dns.query.udp(q, resolver.nameservers[0], timeout=5)
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                dnskey_count += len(rrset)
                got_any = True
            elif rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig_count += len(rrset)
    except Exception:
        pass

    try:
        q = dns.message.make_query(domain, dns.rdatatype.DS, want_dnssec=True)
        resp = dns.query.udp(q, resolver.nameservers[0], timeout=5)
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.DS:
                ds_count += len(rrset)
                got_any = True
    except Exception:
        pass

    if not got_any:
        return None
    return KeyTrapCapture(dnskey_count=dnskey_count, rrsig_count_on_dnskey=rrsig_count, ds_count=ds_count, domain=domain)


def capture_nsec3(domain: str, resolver: dns.resolver.Resolver) -> Nsec3Capture:
    probe = f"tier0fp-probe-nonexistent.{domain}."
    try:
        q = dns.message.make_query(probe, dns.rdatatype.A, want_dnssec=True)
        resp = dns.query.udp(q, resolver.nameservers[0], timeout=5)
        for rrset in resp.authority:
            if rrset.rdtype == dns.rdatatype.NSEC3:
                return Nsec3Capture(iterations=int(rrset[0].iterations), domain=domain)
    except Exception:
        pass
    return Nsec3Capture(iterations=None, domain=domain)


@dataclass
class DomainResult:
    domain: str
    referral_hops: List[ReferralCapture] = field(default_factory=list)
    final_answer: Optional[FinalAnswerCapture] = None
    keytrap: Optional[KeyTrapCapture] = None
    nsec3: Nsec3Capture = None


def run_harness(domains: List[str], delay: float = 0.05, progress_cb=None, resolvers: List[str] = None) -> List[DomainResult]:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = resolvers if resolvers else PUBLIC_RESOLVERS
    resolver.use_edns(edns=0, ednsflags=dns.flags.edns_from_text("DO"), payload=4096)

    results = []
    for i, domain in enumerate(domains):
        r = DomainResult(domain=domain)
        r.referral_hops = walk_referrals(domain, resolver)
        time.sleep(delay)
        r.final_answer = capture_final_answer(domain, resolver)
        time.sleep(delay)
        r.keytrap = capture_keytrap(domain, resolver)
        time.sleep(delay)
        r.nsec3 = capture_nsec3(domain, resolver)
        time.sleep(delay)
        results.append(r)
        if progress_cb:
            progress_cb(i + 1, len(domains), domain)
    return results


def aggregate_results(results: List[DomainResult]) -> dict:
    referral_hops = [h for r in results for h in r.referral_hops]
    final_answers = [r.final_answer for r in results if r.final_answer is not None]
    keytraps = [r.keytrap for r in results if r.keytrap is not None]
    nsec3_applicable = [r.nsec3 for r in results if r.nsec3 is not None and r.nsec3.iterations is not None]

    def _rate(matches, total):
        return {
            "matches": matches,
            "applicable_population": total,
            "fp_pct": round((matches / total * 100), 4) if total else None,
        }

    nxns_matches = sum(1 for h in referral_hops if nxns_nrdelegation(h))
    cacheflush_cname_matches = sum(1 for f in final_answers if cacheflush_cname(f))
    cacheflush_ns_matches = sum(1 for h in referral_hops if cacheflush_ns_referral(h))
    rrset_bloat_matches = sum(1 for h in referral_hops if rrset_bloating(h))
    dnskey_matches = sum(1 for k in keytraps if keytrap_dnskey(k))
    rrsig_matches = sum(1 for k in keytraps if keytrap_rrsig(k))
    ds_matches = sum(1 for k in keytraps if keytrap_ds(k))
    nsec3_matches = sum(1 for n in nsec3_applicable if nsec3_iterations(n))

    return {
        "sample_size": len(results),
        "referral_hops_captured": len(referral_hops),
        "final_answers_captured": len(final_answers),
        "keytrap_captures": len(keytraps),
        "nsec3_applicable_zones": len(nsec3_applicable),
        "rules": {
            "nxns_nrdelegation": _rate(nxns_matches, len(referral_hops)),
            "cacheflush_cname": _rate(cacheflush_cname_matches, len(final_answers)),
            "cacheflush_ns_referral": _rate(cacheflush_ns_matches, len(referral_hops)),
            "rrset_bloating": _rate(rrset_bloat_matches, len(referral_hops)),
            "keytrap_dnskey": _rate(dnskey_matches, len(keytraps)),
            "keytrap_rrsig": _rate(rrsig_matches, len(keytraps)),
            "keytrap_ds": _rate(ds_matches, len(keytraps)),
            "nsec3_iterations": _rate(nsec3_matches, len(nsec3_applicable)),
        },
        "exemplars": {
            "nxns_nrdelegation": [h.domain for h in referral_hops if nxns_nrdelegation(h)][:20],
            "cacheflush_cname": [f.domain for f in final_answers if cacheflush_cname(f)][:20],
            "cacheflush_ns_referral": [h.domain for h in referral_hops if cacheflush_ns_referral(h)][:20],
            "rrset_bloating": [h.domain for h in referral_hops if rrset_bloating(h)][:20],
            "keytrap_dnskey": [k.domain for k in keytraps if keytrap_dnskey(k)][:20],
            "keytrap_rrsig": [k.domain for k in keytraps if keytrap_rrsig(k)][:20],
            "keytrap_ds": [k.domain for k in keytraps if keytrap_ds(k)][:20],
            "nsec3_iterations": [n.domain for n in nsec3_applicable if nsec3_iterations(n)][:20],
        },
    }
