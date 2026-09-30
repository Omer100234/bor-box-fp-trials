from tier0fp.canonicalize import canonicalize_qname


def test_adds_missing_trailing_dot():
    assert canonicalize_qname("example.com").normalized == "example.com."


def test_leaves_existing_trailing_dot_alone():
    assert canonicalize_qname("example.com.").normalized == "example.com."


def test_does_not_collapse_genuine_empty_label_at_end():
    # A name already ending in ".." is a real empty-label anomaly (what R6 targets) --
    # canonicalization must not silently erase it.
    assert canonicalize_qname("example.com..").normalized == "example.com.."


def test_lowercases():
    assert canonicalize_qname("EXAMPLE.COM.").normalized == "example.com."


def test_strips_surrounding_whitespace():
    assert canonicalize_qname("  example.com.  ").normalized == "example.com."


def test_empty_string_is_malformed():
    result = canonicalize_qname("")
    assert result.is_malformed


def test_whitespace_only_is_malformed():
    result = canonicalize_qname("   ")
    assert result.is_malformed


def test_none_is_malformed():
    result = canonicalize_qname(None)
    assert result.is_malformed


def test_punycode_flagged_but_not_altered():
    result = canonicalize_qname("xn--exmple-cua.com.")
    assert result.is_punycode
    assert not result.is_malformed
    assert result.normalized == "xn--exmple-cua.com."
