from tier0fp.pipeline import _parse_ts


def test_seconds_epoch_passes_through_unchanged():
    assert _parse_ts("1636816571") == 1636816571.0


def test_milliseconds_epoch_is_converted_to_seconds():
    # Real value observed in the Mendeley dataset.csv -- undocumented in
    # dataset_description.txt, discovered by profiling the full corpus.
    assert _parse_ts("1624438272607") == 1624438272.607


def test_blank_is_none():
    assert _parse_ts("") is None
    assert _parse_ts(None) is None
