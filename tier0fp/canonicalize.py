"""Single canonicalization function shared by the harness and (to be verified against) the
BOR-BOX engine. See plan §4.4.

The deployed regexes anchor on ``\\.$``; a dataset stored without trailing dots would silently
zero every match, so this is the single most important invariant this module enforces.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CanonResult:
    normalized: str
    is_malformed: bool
    is_punycode: bool


def canonicalize_qname(raw: str) -> CanonResult:
    if raw is None:
        return CanonResult(normalized="", is_malformed=True, is_punycode=False)

    name = raw.strip()
    if name == "":
        return CanonResult(normalized="", is_malformed=True, is_punycode=False)

    name = name.lower()

    # Only ADD a trailing dot when one is entirely missing (the case that would silently
    # zero every \.$-anchored rule). A name that already ends in ".." is a genuine
    # empty-label anomaly and must be left alone so R6 ((\.\.+)) can still see it --
    # collapsing it here would quietly erase the exact signal that rule exists to catch.
    if not name.endswith("."):
        name = name + "."

    is_punycode = "xn--" in name
    return CanonResult(normalized=name, is_malformed=False, is_punycode=is_punycode)
