from tier0fp.response_rules import (
    ReferralCapture,
    FinalAnswerCapture,
    KeyTrapCapture,
    Nsec3Capture,
    nxns_nrdelegation,
    cacheflush_cname,
    cacheflush_ns_referral,
    rrset_bloating,
    keytrap_dnskey,
    keytrap_rrsig,
    keytrap_ds,
    nsec3_iterations,
)


def _referral(nscount, arcount, qr=True, aa=False):
    return ReferralCapture(qr=qr, aa=aa, nscount=nscount, arcount=arcount, hop="test", domain="example.com")


def test_nxns_nrdelegation_matches_high_ns_low_ar():
    assert nxns_nrdelegation(_referral(nscount=11, arcount=9)) is True


def test_nxns_nrdelegation_misses_when_ar_not_low():
    assert nxns_nrdelegation(_referral(nscount=11, arcount=10)) is False


def test_nxns_nrdelegation_misses_boundary_ns_10():
    assert nxns_nrdelegation(_referral(nscount=10, arcount=5)) is False


def test_nxns_nrdelegation_misses_when_authoritative_answer_not_referral():
    assert nxns_nrdelegation(_referral(nscount=20, arcount=1, aa=True)) is False


def test_nxns_nrdelegation_root_to_com_shape_is_not_flagged():
    # The real root->.com referral observed live: NSCOUNT=13, ARCOUNT=11 -- ARCOUNT=11 is
    # not < 10, so this legitimate, extremely common referral shape must NOT be flagged.
    assert nxns_nrdelegation(_referral(nscount=13, arcount=11)) is False


def test_cacheflush_cname_matches_high_ancount():
    assert cacheflush_cname(FinalAnswerCapture(qr=True, ancount=10, domain="x")) is True


def test_cacheflush_cname_misses_boundary_9():
    assert cacheflush_cname(FinalAnswerCapture(qr=True, ancount=9, domain="x")) is False


def test_cacheflush_ns_referral_matches_above_13():
    assert cacheflush_ns_referral(_referral(nscount=14, arcount=0)) is True


def test_cacheflush_ns_referral_misses_classic_13_root_hint_count():
    # The catalog's own stated rationale: legitimate root/TLD referrals top out at 13.
    assert cacheflush_ns_referral(_referral(nscount=13, arcount=0)) is False


def test_rrset_bloating_matches_high_ns_or_ar():
    assert rrset_bloating(_referral(nscount=51, arcount=0)) is True
    assert rrset_bloating(_referral(nscount=0, arcount=51)) is True


def test_rrset_bloating_misses_boundary_50():
    assert rrset_bloating(_referral(nscount=50, arcount=50)) is False


def test_keytrap_dnskey_boundary():
    assert keytrap_dnskey(KeyTrapCapture(dnskey_count=11, rrsig_count_on_dnskey=0, ds_count=0, domain="x")) is True
    assert keytrap_dnskey(KeyTrapCapture(dnskey_count=10, rrsig_count_on_dnskey=0, ds_count=0, domain="x")) is False


def test_keytrap_rrsig_boundary():
    assert keytrap_rrsig(KeyTrapCapture(dnskey_count=0, rrsig_count_on_dnskey=11, ds_count=0, domain="x")) is True
    assert keytrap_rrsig(KeyTrapCapture(dnskey_count=0, rrsig_count_on_dnskey=10, ds_count=0, domain="x")) is False


def test_keytrap_ds_boundary():
    assert keytrap_ds(KeyTrapCapture(dnskey_count=0, rrsig_count_on_dnskey=0, ds_count=11, domain="x")) is True
    assert keytrap_ds(KeyTrapCapture(dnskey_count=0, rrsig_count_on_dnskey=0, ds_count=10, domain="x")) is False


def test_nsec3_iterations_boundary():
    assert nsec3_iterations(Nsec3Capture(iterations=11, domain="x")) is True
    assert nsec3_iterations(Nsec3Capture(iterations=10, domain="x")) is False


def test_nsec3_iterations_real_paypal_value_not_flagged():
    # Real value observed live: paypal.com uses NSEC3 with iterations=10, exactly at the
    # catalog's stated best-practice ceiling -- must not be flagged.
    assert nsec3_iterations(Nsec3Capture(iterations=10, domain="paypal.com")) is False


def test_nsec3_not_applicable_when_zone_has_no_nsec3():
    assert nsec3_iterations(Nsec3Capture(iterations=None, domain="cloudflare.com")) is False
