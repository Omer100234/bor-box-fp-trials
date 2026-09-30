from tier0fp.canonicalize import canonicalize_qname
from tier0fp.golden_fixtures import GOLDEN_CASES
from tier0fp.rules import (
    evaluate_independent,
    evaluate_system,
    evaluate_attack_groups,
    R5_ALLOW_RULES,
    SYSTEM_ORDER,
)


def _ids():
    seen = set()
    for name, _, _ in GOLDEN_CASES:
        assert name not in seen, f"duplicate golden case name {name!r}"
        seen.add(name)
    return [name for name, _, _ in GOLDEN_CASES]


def test_no_duplicate_case_names():
    _ids()


import pytest


@pytest.mark.parametrize("case_name,raw,expected", GOLDEN_CASES, ids=[c[0] for c in GOLDEN_CASES])
def test_golden_case(case_name, raw, expected):
    canon = canonicalize_qname(raw)
    assert not canon.is_malformed, f"{case_name}: unexpectedly malformed"
    got = evaluate_independent(canon.normalized)
    for rule_id, expected_value in expected.items():
        assert got[rule_id] == expected_value, (
            f"{case_name}: rule {rule_id} on {canon.normalized!r} "
            f"expected {expected_value}, got {got[rule_id]}"
        )


def test_system_mode_allow_precedence():
    # Matches R5's cloudfront.net ALLOW entry AND independently matches R1 (exactly
    # 3 labels, first label 8+ alnum chars) -- demonstrates the differencing the plan
    # (§5) uses to show how much the ALLOW list "buys" over raw R1.
    qname = "abcdefgh.cloudfront.net."
    indep = evaluate_independent(qname)
    assert indep["R1"] is True

    system_outcome = evaluate_system(qname)
    assert system_outcome == "R5_ALLOW"


def test_system_mode_limit_when_no_allow_match():
    qname = "abcdefgh.example.com."
    assert evaluate_system(qname) == "R1"


def test_system_mode_no_match_passthrough():
    qname = "www.example.com."
    assert evaluate_system(qname) is None


def test_allow_list_has_eleven_entries():
    assert len(R5_ALLOW_RULES) == 11


def test_attack_group_water_torture_is_union_of_r1_to_r4():
    # Matches only R2 (6-label chain), not R1/R3/R4 -- the water_torture group must still
    # fire since it's a union (OR), not requiring all four.
    qname = "a.b.c.d.e.f."
    groups = evaluate_attack_groups(qname)
    assert groups["water_torture"]["independent"] is True
    assert groups["tudoor_qname_only"]["independent"] is False


def test_attack_group_water_torture_gated_by_allow_list():
    # Matches R1 independently, but is also on the water-torture ALLOW list -- the group's
    # system-mode result must be suppressed even though independent is True.
    qname = "abcdefgh.cloudfront.net."
    groups = evaluate_attack_groups(qname)
    assert groups["water_torture"]["independent"] is True
    assert groups["water_torture"]["system"] is False


def test_attack_group_tudoor_not_gated_by_water_torture_allow_list():
    # An empty-label name under an ALLOW-listed CDN domain: the water-torture ALLOW list
    # must NOT suppress TuDoor's group, since the catalog scopes that ALLOW list to
    # water-torture only.
    qname = "a..cloudfront.net."
    groups = evaluate_attack_groups(qname)
    assert groups["tudoor_qname_only"]["independent"] is True
    assert groups["tudoor_qname_only"]["system"] is True


def test_attack_group_no_match():
    qname = "www.example.com."
    groups = evaluate_attack_groups(qname)
    assert groups["water_torture"]["independent"] is False
    assert groups["water_torture"]["system"] is False
    assert groups["tudoor_qname_only"]["independent"] is False
    assert groups["tudoor_qname_only"]["system"] is False
