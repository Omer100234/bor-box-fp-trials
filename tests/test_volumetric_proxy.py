from tier0fp.volumetric_proxy import VolumetricQPSProxyState


def test_single_packet_rate_is_one():
    s = VolumetricQPSProxyState()
    rate = s.observe("example.com", 100.0)
    assert rate == 1
    assert s.flag_count[5] == 0  # below every threshold


def test_burst_within_window_raises_rate():
    s = VolumetricQPSProxyState()
    for i in range(10):
        rate = s.observe("example.com", 100.0 + i * 0.05)  # 10 packets inside 0.45s
    assert rate == 10
    assert s.flag_count[10] == 1
    assert s.flag_count[20] == 0


def test_packets_outside_window_do_not_accumulate():
    s = VolumetricQPSProxyState()
    s.observe("example.com", 100.0)
    s.observe("example.com", 100.0)
    rate = s.observe("example.com", 102.0)  # 2s later -- outside the 1s window
    assert rate == 1


def test_different_2lds_tracked_independently():
    s = VolumetricQPSProxyState()
    for i in range(5):
        s.observe("a.com", 100.0 + i * 0.01)
    rate_b = s.observe("b.com", 100.02)
    assert rate_b == 1


def test_total_benign_counts_every_observation():
    s = VolumetricQPSProxyState()
    s.observe("a.com", 1.0)
    s.observe("b.com", 1.0)
    s.observe("a.com", 1.5)
    assert s.total_benign == 3


def test_stale_2ld_entries_are_evicted_from_memory():
    s = VolumetricQPSProxyState()
    s.observe("a.com", 100.0)
    assert "a.com" in s._queues
    # advance far past the window on an unrelated key; a.com's queue empties and its
    # dict entry should be reclaimed via the global recency FIFO, not left dangling.
    for i in range(5):
        s.observe("b.com", 105.0 + i)
    assert "a.com" not in s._queues


def test_to_summary_fraction_matches_flag_count():
    s = VolumetricQPSProxyState()
    for i in range(20):
        s.observe("flood.com", 100.0 + i * 0.01)  # 20 packets inside 0.19s
    summary = s.to_summary()
    assert summary["total_benign"] == 20
    assert summary["thresholds"]["20"]["flagged_count"] == 1
    assert summary["thresholds"]["20"]["fraction"] == 1 / 20
    assert summary["max_single_2ld_rate_seen"] == 20
