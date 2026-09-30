"""Plan §6.1/§6.3 engine-parity checks.

Two things this project can actually verify in this environment:
  1. Python >=3.11 is pinned (required for the {8,}+ possessive quantifier R1 uses).
  2. The possessive (R1) and non-possessive (R1_NONPOSSESSIVE) variants produce an
     identical match set on both the golden fixtures and a larger randomized corpus --
     turning "they should be identical for an anchored pattern like this" into a checked
     fact rather than an assumption.

What this project CANNOT verify here: parity against the actual BOR-BOX DFA engine via
the Scapy/Docker testbed (plan §6.3) -- there is no BOR-BOX instance in this environment.
That comparison must be run separately, against the real box, before any measurement here
is treated as authoritative.
"""
import random
import string
import sys

import pytest

from tier0fp.golden_fixtures import GOLDEN_CASES
from tier0fp.canonicalize import canonicalize_qname
from tier0fp.rules import R1, R1_NONPOSSESSIVE


def test_python_version_supports_possessive_quantifiers():
    assert sys.version_info >= (3, 11), (
        "R1's {8,}+ possessive quantifier requires Python 3.11+; pin the interpreter "
        "or link the box's own DFA engine instead of Python re (plan §6.1)."
    )


def test_r1_variants_agree_on_golden_fixtures():
    for case_name, raw, _ in GOLDEN_CASES:
        canon = canonicalize_qname(raw)
        assert R1.matches(canon.normalized) == R1_NONPOSSESSIVE.matches(canon.normalized), (
            f"{case_name}: possessive/non-possessive R1 disagree on {canon.normalized!r}"
        )


def _random_qname(rng: random.Random) -> str:
    n_labels = rng.randint(1, 8)
    labels = []
    for _ in range(n_labels):
        length = rng.randint(0, 12)
        alphabet = string.ascii_lowercase + string.digits + ("-" if rng.random() < 0.1 else "")
        labels.append("".join(rng.choice(alphabet) for _ in range(length)) or "x")
    return ".".join(labels) + "."


def test_r1_variants_agree_on_randomized_corpus():
    rng = random.Random(20260912)
    mismatches = []
    for _ in range(20_000):
        qname = _random_qname(rng)
        a, b = R1.matches(qname), R1_NONPOSSESSIVE.matches(qname)
        if a != b:
            mismatches.append((qname, a, b))
    assert not mismatches, f"possessive/non-possessive R1 disagreed on {len(mismatches)} names, e.g. {mismatches[:5]}"


@pytest.mark.skip(reason="Requires a live BOR-BOX + Docker/Scapy testbed, not available in this environment (plan §6.3)")
def test_golden_fixtures_against_real_borbox_engine():
    pass
