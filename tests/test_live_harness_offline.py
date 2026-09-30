"""Offline-only tests for live_harness.py: aggregation logic and domain-list hygiene.
No network access -- actual live DNS queries are exercised only via the CLI script, not
part of the standard test suite (network-dependent and non-deterministic by nature)."""
from tier0fp.live_harness import (
    DomainResult,
    aggregate_results,
    build_sample_domains,
    clean_domain_list,
)
from tier0fp.response_rules import FinalAnswerCapture, KeyTrapCapture, Nsec3Capture, ReferralCapture


def test_clean_domain_list_drops_non_domains():
    raw = ["local.local", "ddns.net:8080", "google.com", "spamhaus.org"]
    cleaned = clean_domain_list(raw)
    assert "local.local" not in cleaned
    assert "ddns.net:8080" not in cleaned
    assert cleaned == ["google.com", "spamhaus.org"]


def test_build_sample_domains_dedupes_and_adds_supplement():
    sample = build_sample_domains(["google.com", "local.local"])
    assert "google.com" in sample
    assert "local.local" not in sample
    assert "paypal.com" in sample  # from the DNSSEC diversity supplement
    assert len(sample) == len(set(sample))  # no duplicates


def test_aggregate_results_computes_rates_correctly():
    results = [
        DomainResult(
            domain="a.com",
            referral_hops=[ReferralCapture(qr=True, aa=False, nscount=11, arcount=9, hop="root->tld", domain="a.com")],
            final_answer=FinalAnswerCapture(qr=True, ancount=10, domain="a.com"),
            keytrap=KeyTrapCapture(dnskey_count=11, rrsig_count_on_dnskey=1, ds_count=1, domain="a.com"),
            nsec3=Nsec3Capture(iterations=11, domain="a.com"),
        ),
        DomainResult(
            domain="b.com",
            referral_hops=[ReferralCapture(qr=True, aa=False, nscount=13, arcount=11, hop="root->tld", domain="b.com")],
            final_answer=FinalAnswerCapture(qr=True, ancount=1, domain="b.com"),
            keytrap=KeyTrapCapture(dnskey_count=2, rrsig_count_on_dnskey=1, ds_count=1, domain="b.com"),
            nsec3=Nsec3Capture(iterations=None, domain="b.com"),  # no NSEC3 -- excluded from denominator
        ),
    ]
    agg = aggregate_results(results)

    assert agg["referral_hops_captured"] == 2
    assert agg["rules"]["nxns_nrdelegation"]["matches"] == 1
    assert agg["rules"]["nxns_nrdelegation"]["applicable_population"] == 2
    assert agg["rules"]["nxns_nrdelegation"]["fp_pct"] == 50.0

    assert agg["rules"]["cacheflush_cname"]["matches"] == 1
    assert agg["rules"]["cacheflush_cname"]["applicable_population"] == 2

    assert agg["rules"]["keytrap_dnskey"]["matches"] == 1
    assert agg["rules"]["keytrap_dnskey"]["applicable_population"] == 2

    # nsec3 denominator excludes the domain with no NSEC3 at all.
    assert agg["rules"]["nsec3_iterations"]["applicable_population"] == 1
    assert agg["rules"]["nsec3_iterations"]["matches"] == 1
    assert agg["rules"]["nsec3_iterations"]["fp_pct"] == 100.0


def test_aggregate_results_handles_empty_population_as_none_fp_pct():
    agg = aggregate_results([DomainResult(domain="unresolvable.example")])
    assert agg["rules"]["nxns_nrdelegation"]["fp_pct"] is None
    assert agg["rules"]["nsec3_iterations"]["fp_pct"] is None
