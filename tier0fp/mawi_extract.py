"""Extract DNS response header fields from a real MAWI backbone-traffic pcap.gz capture
and apply the pure header-count response-side rules (catalog §3, §4, §5, §11).

MAWI captures use a 96-byte snap length (packets truncated for privacy/storage), which is
irrelevant to these four rules specifically: NXNS/NRDelegation, both CacheFlush variants,
and RRSet Bloating all read only the fixed 12-byte DNS header (ID, flags, QDCOUNT, ANCOUNT,
NSCOUNT, ARCOUNT) -- present in full even in a heavily truncated packet, since Ethernet(14)
+ IP(20) + UDP(8) + DNS header(12) = 54 bytes, comfortably inside a 96-byte snap length.
KeyTrap (needs to distinguish DNSKEY/RRSIG/DS record TYPEs within the answer, which can be
truncated away) and NSEC3 (needs the NSEC3 record's iterations field, deep in RDATA) are
NOT attempted here -- those stay measured via the live harness (live_harness.py) only.
"""
from __future__ import annotations

import gzip
import struct
from dataclasses import dataclass

import dpkt

from .r7_proxy import R7QueueProxyState
from .response_rules import (
    ReferralCapture,
    FinalAnswerCapture,
    cacheflush_cname,
    cacheflush_ns_referral,
    nxns_nrdelegation,
    rrset_bloating,
)

DNS_PORT = 53


def _open_pcap_reader(pcap_path: str):
    """MAWI captures are always .gz; other sources (e.g. CTU-Normal, used to cross-check
    the cache-poisoning proxy against a capture that actually preserves DNS payload) ship
    plain .pcap. Dispatch on extension so callers don't have to care which kind they have."""
    if str(pcap_path).endswith(".gz"):
        f = gzip.open(pcap_path, "rb")
    else:
        f = open(pcap_path, "rb")
    return f, dpkt.pcap.Reader(f)


@dataclass
class MawiDnsStats:
    total_dns_packets: int = 0
    responses: int = 0
    referral_like: int = 0  # QR=1, AA=0 -- treated as a ReferralCapture for §3/§5/§11
    final_answer_like: int = 0  # QR=1, AA=1 or ANCOUNT>0 -- treated as a FinalAnswerCapture for §4
    nxns_matches: int = 0
    cacheflush_cname_matches: int = 0
    cacheflush_ns_matches: int = 0
    rrset_bloat_matches: int = 0
    max_nscount: int = 0
    max_arcount: int = 0
    max_ancount: int = 0
    parse_errors: int = 0


def _parse_dns_header(payload: bytes):
    """Manually unpack the fixed 12-byte DNS header. Returns None if too short to have a
    header, or if the opcode isn't standard QUERY (0) -- a passive backbone capture
    inevitably includes some fraction of garbage/corrupted/non-DNS traffic that happens to
    share port 53 (observed directly in this corpus: a single packet with opcode=10, an
    unassigned/invalid value, and a nonsensical QDCOUNT of 12,597). The catalog's attacks
    are all standard-resolution abuse (opcode=QUERY) anyway, so this filter also matches
    the traffic class the rules are meant to evaluate."""
    if len(payload) < 12:
        return None
    _id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", payload[:12])
    opcode = (flags >> 11) & 0x0F
    if opcode != 0:
        return None
    qr = bool(flags & 0x8000)
    aa = bool(flags & 0x0400)
    return qr, aa, qdcount, ancount, nscount, arcount


def _parse_question_qname(payload: bytes, offset: int = 12):
    """Parse just the QNAME out of the question section starting right after the fixed
    12-byte header. No compression-pointer handling needed: the question name is always
    the *first* name in a DNS message, so it can never legally contain a backward
    compression pointer (there is nothing earlier in the message to point at) -- any
    0xC0-flagged length byte here means something is wrong, not a real compressed name.
    Returns the dotted, trailing-dot, lowercased name, or None if the packet's snap-length
    truncation cut the label sequence short (a real MAWI phenomenon: 96-byte captures leave
    only ~42 bytes for Eth/IP/UDP-stripped DNS payload beyond the header, per this module's
    docstring -- callers must exclude a None here from any denominator, not treat it as a
    non-match)."""
    labels = []
    i = offset
    n = len(payload)
    while i < n:
        length = payload[i]
        if length == 0:
            return (".".join(labels) + "." if labels else ".")
        if length & 0xC0:
            return None
        i += 1
        if i + length > n:
            return None
        labels.append(payload[i:i + length].decode("ascii", errors="replace").lower())
        i += length
    return None


def extract_cache_poisoning_signatures(
    pcap_gz_path: str,
    window_size: int = 100,
    threshold: int = 5,
    max_packets: int = None,
    require_qname: bool = True,
) -> dict:
    """Catalog §12 (Cache Poisoning): 'QR=1 AND HEADER EXACT EXCEPT txid', the same
    similarity mechanism as TsuNAME (§7), gated to responses only. Per the header field
    definition, 'HEADER EXACT EXCEPT txid' alone is (flags, QDCOUNT, ANCOUNT, NSCOUNT,
    ARCOUNT) -- coarse, since it ignores the question itself. When `require_qname=True`
    (the default, intended for a capture with real payload) this augments that with the
    QNAME -- a deliberate, disclosed deviation from the literal rule text, chosen because
    it's a much more realistic proxy for "the same forged packet got replayed" than a
    header-shape coincidence between unrelated responses.

    `require_qname=False` falls back to the pure header-only signature and is REQUIRED for
    this project's actual MAWI capture (data/mawi/200701011400.dump.gz): confirmed by direct
    inspection that 100% of its 1,012,001 DNS packets (query and response alike) have
    exactly 12 bytes of DNS payload -- the fixed header only, zero question-section bytes,
    for every single packet, not a truncated-tail subset. The pcap's own snap-length field
    claims 96 bytes; the packets were evidently captured shorter than that at collection
    time regardless. So on this capture, QNAME is not a partially-missing field to work
    around -- it is completely absent, and require_qname=True would report a false 0.00%
    (n=0) rather than a real number.

    Window is scoped to the response (QR=1) substream only -- non-response packets never
    advance or interrupt the sliding window. This is the only rule in this project
    measurable exclusively from MAWI: it needs real response headers (absent from the
    client-facing Mendeley corpus, same structural gap as TuDoor's QR=1 gate) AND packet
    arrival order (absent from the live harness's per-domain sampling)."""
    proxy = R7QueueProxyState(window_size=window_size, threshold=threshold)
    total_responses = 0
    qname_unavailable = 0

    f, reader = _open_pcap_reader(pcap_gz_path)
    with f:
        for i, (_ts, buf) in enumerate(reader):
            if max_packets and i >= max_packets:
                break
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                transport = ip.data
                if isinstance(transport, dpkt.udp.UDP):
                    sport, dport, payload = transport.sport, transport.dport, transport.data
                elif isinstance(transport, dpkt.tcp.TCP):
                    sport, dport, payload = transport.sport, transport.dport, transport.data
                    if len(payload) >= 2:
                        payload = payload[2:]
                else:
                    continue
                if sport != DNS_PORT and dport != DNS_PORT:
                    continue
            except Exception:
                continue

            payload = bytes(payload)
            parsed = _parse_dns_header(payload)
            if parsed is None:
                continue
            qr, _aa, qdcount, ancount, nscount, arcount = parsed
            if not qr:
                continue  # window is response-only, per the question above

            qname_part = ""
            if require_qname:
                if qdcount < 1:
                    qname_unavailable += 1
                    continue
                qname = _parse_question_qname(payload)
                if qname is None:
                    qname_unavailable += 1
                    continue
                qname_part = f"|{qname}"

            # Full 16-bit flags word (not just AA) for a genuinely "exact except txid"
            # comparison -- opcode is always 0 and QR always 1 here (both already filtered
            # by _parse_dns_header above), so what actually varies packet-to-packet is
            # AA/TC/RD/RA/Z/RCODE, all of which live in this field.
            flags_raw = struct.unpack(">H", payload[2:4])[0]
            total_responses += 1
            signature = f"{flags_raw}|{qdcount}|{ancount}|{nscount}|{arcount}{qname_part}"
            proxy.observe(signature)

    summary = proxy.to_summary()
    summary["total_responses_in_window"] = total_responses
    summary["responses_excluded_qname_unavailable"] = qname_unavailable
    return summary


SIG_RRTYPE = 24  # RFC 2931 / IANA DNS RR type 24


def _skip_name(payload: bytes, offset: int):
    """Advance past one (possibly compressed) DNS name and return the offset immediately
    after it -- WITHOUT resolving what a compression pointer points to. That's safe here:
    per RFC 1035 a name is either a label sequence ending in a zero-length label, or a
    label sequence ending in a 2-byte pointer, or a bare 2-byte pointer -- in every case the
    pointer, if present, is the name's last two bytes on the wire, so skipping it (not
    following it) is all that's needed to find where the *next* field starts."""
    n = len(payload)
    i = offset
    while i < n:
        length = payload[i]
        if length == 0:
            return i + 1
        if length & 0xC0:
            return i + 2
        i += 1 + length
        if i > n:
            return None
    return None


def _skip_rr(payload: bytes, offset: int):
    """Skip one resource record (name + fixed TYPE/CLASS/TTL/RDLENGTH + RDATA) and return
    (next_offset, rr_type) -- generic across every RR type, since it never decodes RDATA,
    only uses RDLENGTH to skip over it. This is what lets SIG (type 24, and any other
    type dpkt's own decoder doesn't implement) pass through safely instead of raising."""
    name_end = _skip_name(payload, offset)
    if name_end is None or name_end + 10 > len(payload):
        return None
    rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", payload[name_end:name_end + 10])
    rdata_end = name_end + 10 + rdlength
    if rdata_end > len(payload):
        return None
    return rdata_end, rtype


def _additional_section_rr_types(payload: bytes):
    """Manually walk QUESTION -> ANSWER -> AUTHORITY (skipped, not needed) -> ADDITIONAL,
    returning the list of RR TYPE values present in the additional section, or None if the
    message is malformed/truncated partway through. Deliberately does not use dpkt's
    dns.DNS() parser: that parser calls a per-type RDATA decoder and raises UnpackError on
    any type it doesn't implement -- including SIG (24), the exact type this function
    exists to detect. A real SIG(0) query would silently show up as a "parse error"
    instead of a match under dpkt's parser; this hand-rolled walker never decodes RDATA
    content at all, so it can't fail on an unsupported type."""
    parsed = _parse_dns_header(payload)
    if parsed is None:
        return None
    _qr, _aa, qdcount, ancount, nscount, arcount = parsed

    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(payload, offset)
        if offset is None or offset + 4 > len(payload):
            return None
        offset += 4  # QTYPE + QCLASS

    for _ in range(ancount + nscount):
        result = _skip_rr(payload, offset)
        if result is None:
            return None
        offset, _rtype = result

    types = []
    for _ in range(arcount):
        result = _skip_rr(payload, offset)
        if result is None:
            return None
        offset, rtype = result
        types.append(rtype)
    return types


def extract_sig0_signatures(pcap_path: str, max_packets: int = None) -> dict:
    """Catalog §9 (SIG(0) Signature Flood, CVE-2024-1975): 'QR=0 AND NUMBER OF SIG > 0
    LIMIT' -- a client-signed *query* (RFC 2931) carrying a SIG record in its additional
    section. Unlike every other response-side rule in this project, this one is measured
    on QUERY packets, so it needs a source with full, untruncated query payloads (MAWI is
    unusable here for the same reason it was unusable for Cache Poisoning's QNAME: its
    packets carry only the fixed 12-byte header, no additional section at all).

    `additional_unparseable` counts queries whose additional section couldn't be walked at
    all (truncated/malformed) -- excluded from the FP-rate denominator, same convention as
    `responses_excluded_qname_unavailable` elsewhere in this module."""
    total_queries = 0
    sig_matches = 0
    additional_unparseable = 0

    f, reader = _open_pcap_reader(pcap_path)
    with f:
        for i, (_ts, buf) in enumerate(reader):
            if max_packets and i >= max_packets:
                break
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                transport = ip.data
                if isinstance(transport, dpkt.udp.UDP):
                    sport, dport, payload = transport.sport, transport.dport, transport.data
                elif isinstance(transport, dpkt.tcp.TCP):
                    sport, dport, payload = transport.sport, transport.dport, transport.data
                    if len(payload) >= 2:
                        payload = payload[2:]
                else:
                    continue
                if sport != DNS_PORT and dport != DNS_PORT:
                    continue
            except Exception:
                continue

            payload = bytes(payload)
            parsed = _parse_dns_header(payload)
            if parsed is None:
                continue
            qr = parsed[0]
            if qr:
                continue  # this rule is query-side only (QR=0)

            total_queries += 1
            types = _additional_section_rr_types(payload)
            if types is None:
                additional_unparseable += 1
                continue
            if SIG_RRTYPE in types:
                sig_matches += 1

    denom = total_queries - additional_unparseable
    return {
        "total_queries": total_queries,
        "additional_unparseable": additional_unparseable,
        "sig_matches": sig_matches,
        "fp_pct": round((sig_matches / denom * 100), 6) if denom else None,
    }


def extract_and_apply_rules(pcap_gz_path: str, max_packets: int = None) -> MawiDnsStats:
    stats = MawiDnsStats()

    f, reader = _open_pcap_reader(pcap_gz_path)
    with f:
        for i, (_ts, buf) in enumerate(reader):
            if max_packets and i >= max_packets:
                break
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                transport = ip.data
                if isinstance(transport, dpkt.udp.UDP):
                    sport, dport, payload = transport.sport, transport.dport, transport.data
                elif isinstance(transport, dpkt.tcp.TCP):
                    sport, dport, payload = transport.sport, transport.dport, transport.data
                    if len(payload) >= 2:
                        payload = payload[2:]  # TCP DNS has a 2-byte length prefix
                else:
                    continue
                if sport != DNS_PORT and dport != DNS_PORT:
                    continue
            except Exception:
                stats.parse_errors += 1
                continue

            parsed = _parse_dns_header(bytes(payload))
            if parsed is None:
                stats.parse_errors += 1
                continue

            qr, aa, qdcount, ancount, nscount, arcount = parsed
            stats.total_dns_packets += 1
            if not qr:
                continue
            stats.responses += 1
            stats.max_nscount = max(stats.max_nscount, nscount)
            stats.max_arcount = max(stats.max_arcount, arcount)
            stats.max_ancount = max(stats.max_ancount, ancount)

            referral = ReferralCapture(qr=qr, aa=aa, nscount=nscount, arcount=arcount, hop="mawi", domain="")
            if nxns_nrdelegation(referral):
                stats.nxns_matches += 1
            if cacheflush_ns_referral(referral):
                stats.cacheflush_ns_matches += 1
            if rrset_bloating(referral):
                stats.rrset_bloat_matches += 1
            if not aa:
                stats.referral_like += 1

            final = FinalAnswerCapture(qr=qr, ancount=ancount, domain="")
            if cacheflush_cname(final):
                stats.cacheflush_cname_matches += 1
            stats.final_answer_like += 1

    return stats


def summarize(stats: MawiDnsStats) -> dict:
    def rate(n):
        return round((n / stats.responses * 100), 6) if stats.responses else None

    return {
        "total_dns_packets": stats.total_dns_packets,
        "responses": stats.responses,
        "parse_errors": stats.parse_errors,
        "max_observed": {
            "nscount": stats.max_nscount,
            "arcount": stats.max_arcount,
            "ancount": stats.max_ancount,
        },
        "rules": {
            "nxns_nrdelegation": {"matches": stats.nxns_matches, "fp_pct": rate(stats.nxns_matches)},
            "cacheflush_cname": {"matches": stats.cacheflush_cname_matches, "fp_pct": rate(stats.cacheflush_cname_matches)},
            "cacheflush_ns_referral": {"matches": stats.cacheflush_ns_matches, "fp_pct": rate(stats.cacheflush_ns_matches)},
            "rrset_bloating": {"matches": stats.rrset_bloat_matches, "fp_pct": rate(stats.rrset_bloat_matches)},
        },
    }
