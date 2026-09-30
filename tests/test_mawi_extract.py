import struct

from tier0fp.mawi_extract import (
    _parse_dns_header,
    _parse_question_qname,
    _additional_section_rr_types,
    _skip_name,
    SIG_RRTYPE,
)


def _header(qr, aa, opcode, qdcount, ancount, nscount, arcount):
    flags = (qr << 15) | (opcode << 11) | (aa << 10)
    return struct.pack(">HHHHHH", 0x1234, flags, qdcount, ancount, nscount, arcount)


def test_parses_standard_query_response_header():
    payload = _header(qr=1, aa=0, opcode=0, qdcount=1, ancount=0, nscount=13, arcount=1)
    result = _parse_dns_header(payload)
    assert result == (True, False, 1, 0, 13, 1)


def test_rejects_non_standard_opcode():
    # Real corpus finding: a single garbage packet with opcode=10 (unassigned) and
    # QDCOUNT=12597 must be excluded, not treated as legitimate DNS.
    payload = _header(qr=1, aa=0, opcode=10, qdcount=12597, ancount=63744, nscount=22277, arcount=41523)
    assert _parse_dns_header(payload) is None


def test_rejects_too_short_payload():
    assert _parse_dns_header(b"\x00" * 8) is None


def test_parses_query_not_response():
    payload = _header(qr=0, aa=0, opcode=0, qdcount=1, ancount=0, nscount=0, arcount=0)
    result = _parse_dns_header(payload)
    assert result[0] is False  # qr


def _encode_qname_labels(labels):
    out = b""
    for label in labels:
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def test_parse_question_qname_normal_name():
    header = _header(qr=1, aa=0, opcode=0, qdcount=1, ancount=0, nscount=0, arcount=0)
    question = _encode_qname_labels(["example", "com"]) + b"\x00\x01\x00\x01"  # + QTYPE/QCLASS
    assert _parse_question_qname(header + question) == "example.com."


def test_parse_question_qname_root():
    header = _header(qr=1, aa=0, opcode=0, qdcount=1, ancount=0, nscount=0, arcount=0)
    question = b"\x00" + b"\x00\x01\x00\x01"  # root name: single zero-length label
    assert _parse_question_qname(header + question) == "."


def test_parse_question_qname_truncated_mid_label_returns_none():
    header = _header(qr=1, aa=0, opcode=0, qdcount=1, ancount=0, nscount=0, arcount=0)
    question = bytes([7]) + b"exam"  # claims a 7-byte label but only 4 bytes follow
    assert _parse_question_qname(header + question) is None


def test_parse_question_qname_compression_pointer_returns_none():
    header = _header(qr=1, aa=0, opcode=0, qdcount=1, ancount=0, nscount=0, arcount=0)
    question = bytes([0xC0, 0x0C])  # a compression pointer -- illegal in a question name
    assert _parse_question_qname(header + question) is None


def test_parse_question_qname_lowercases():
    header = _header(qr=1, aa=0, opcode=0, qdcount=1, ancount=0, nscount=0, arcount=0)
    question = _encode_qname_labels(["EXAMPLE", "COM"]) + b"\x00\x01\x00\x01"
    assert _parse_question_qname(header + question) == "example.com."


def _rr(name_labels, rtype, rdata=b""):
    return _encode_qname_labels(name_labels) + struct.pack(">HHIH", rtype, 1, 0, len(rdata)) + rdata


def test_additional_section_detects_sig_record_dpkt_cannot_parse():
    # This is the exact scenario that breaks dpkt.dns.DNS() (raises UnpackError on RR type
    # 24) -- the manual walker must handle it without decoding the SIG RDATA at all.
    header = _header(qr=0, aa=0, opcode=0, qdcount=1, ancount=0, nscount=0, arcount=1)
    question = _encode_qname_labels(["example", "com"]) + struct.pack(">HH", 1, 1)
    additional = _rr([], SIG_RRTYPE, rdata=b"\x00" * 18)  # root name, arbitrary SIG rdata
    payload = header + question + additional
    types = _additional_section_rr_types(payload)
    assert types == [SIG_RRTYPE]


def test_additional_section_no_sig_record():
    header = _header(qr=0, aa=0, opcode=0, qdcount=1, ancount=0, nscount=0, arcount=1)
    question = _encode_qname_labels(["example", "com"]) + struct.pack(">HH", 1, 1)
    additional = _rr([], 41, rdata=b"")  # OPT (EDNS), not SIG
    payload = header + question + additional
    types = _additional_section_rr_types(payload)
    assert types == [41]
    assert SIG_RRTYPE not in types


def test_additional_section_no_additional_records():
    header = _header(qr=0, aa=0, opcode=0, qdcount=1, ancount=0, nscount=0, arcount=0)
    question = _encode_qname_labels(["example", "com"]) + struct.pack(">HH", 1, 1)
    payload = header + question
    assert _additional_section_rr_types(payload) == []


def test_additional_section_returns_none_when_truncated():
    header = _header(qr=0, aa=0, opcode=0, qdcount=1, ancount=0, nscount=0, arcount=1)
    question = _encode_qname_labels(["example", "com"]) + struct.pack(">HH", 1, 1)
    payload = header + question  # claims arcount=1 but no additional record bytes follow
    assert _additional_section_rr_types(payload) is None


def test_additional_section_skips_answer_and_authority_before_additional():
    header = _header(qr=0, aa=0, opcode=0, qdcount=1, ancount=1, nscount=1, arcount=1)
    question = _encode_qname_labels(["example", "com"]) + struct.pack(">HH", 1, 1)
    answer = _rr(["example", "com"], 1, rdata=b"\x01\x02\x03\x04")  # A record
    authority = _rr(["com"], 2, rdata=b"\x03ns1\x00")  # NS record
    additional = _rr([], SIG_RRTYPE, rdata=b"\x00" * 18)
    payload = header + question + answer + authority + additional
    assert _additional_section_rr_types(payload) == [SIG_RRTYPE]


def test_skip_name_handles_compression_pointer():
    # A bare 2-byte compression pointer must advance exactly 2 bytes, not attempt to
    # follow/resolve it.
    payload = b"\x00" * 12 + b"\xc0\x0c" + b"TAIL"
    end = _skip_name(payload, 12)
    assert end == 14
    assert payload[end:end + 4] == b"TAIL"
