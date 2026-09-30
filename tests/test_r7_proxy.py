from tier0fp.r7_proxy import R7ProxyState, R7QueueProxyState, THRESHOLDS_SECONDS


def test_repeat_within_threshold_counted():
    state = R7ProxyState()
    state.observe("client-a", "example.com.", 100.0)
    state.observe("client-a", "example.com.", 100.05)  # 50ms gap
    summary = state.to_summary()
    assert summary["thresholds"]["0.1"]["in_burst_count"] == 1
    assert summary["thresholds"]["0.5"]["in_burst_count"] == 1
    assert summary["thresholds"]["1.0"]["in_burst_count"] == 1


def test_repeat_outside_all_thresholds_not_counted():
    state = R7ProxyState()
    state.observe("client-a", "example.com.", 100.0)
    state.observe("client-a", "example.com.", 105.0)  # 5s gap
    summary = state.to_summary()
    for t in THRESHOLDS_SECONDS:
        assert summary["thresholds"][str(t)]["in_burst_count"] == 0


def test_different_qname_same_client_not_grouped():
    state = R7ProxyState()
    state.observe("client-a", "a.example.com.", 100.0)
    state.observe("client-a", "b.example.com.", 100.01)
    summary = state.to_summary()
    for t in THRESHOLDS_SECONDS:
        assert summary["thresholds"][str(t)]["in_burst_count"] == 0


def test_different_client_same_qname_not_grouped():
    state = R7ProxyState()
    state.observe("client-a", "example.com.", 100.0)
    state.observe("client-b", "example.com.", 100.01)
    summary = state.to_summary()
    for t in THRESHOLDS_SECONDS:
        assert summary["thresholds"][str(t)]["in_burst_count"] == 0


def test_total_benign_counts_every_observation():
    state = R7ProxyState()
    for i in range(5):
        state.observe("client-a", "example.com.", 100.0 + i)
    assert state.to_summary()["total_benign"] == 5


def test_memory_bounded_with_many_distinct_keys_spread_over_time():
    # Regression test for the OOM that killed a real 35M-row run: one dict entry per
    # distinct (client, qname) pair ever seen, unbounded over a 26-hour corpus. Each key
    # here is observed exactly once, 2 seconds apart (beyond MAX_THRESHOLD_SECONDS), so
    # every earlier key should be evicted well before the internal dict can grow to match
    # the full 200,000-key population.
    state = R7ProxyState()
    for i in range(200_000):
        state.observe(f"client-{i}", f"host{i}.example.com.", i * 2.0)
    assert len(state._last_ts) < 100
    assert state.to_summary()["total_benign"] == 200_000


def test_burst_detection_still_correct_with_interleaved_keys_near_eviction_boundary():
    # Several distinct keys interleaved close to the 1.0s eviction boundary must not have
    # their legitimate repeat matches evicted out from under them.
    state = R7ProxyState()
    state.observe("client-a", "a.example.com.", 0.0)
    state.observe("client-b", "b.example.com.", 0.2)
    state.observe("client-c", "c.example.com.", 0.4)
    state.observe("client-a", "a.example.com.", 0.9)  # 0.9s gap, still within 1.0s threshold
    summary = state.to_summary()
    assert summary["thresholds"]["1.0"]["in_burst_count"] == 1
    assert summary["thresholds"]["0.5"]["in_burst_count"] == 0


def test_queue_proxy_does_not_flag_below_threshold():
    state = R7QueueProxyState(window_size=100, threshold=5)
    for _ in range(4):
        assert state.observe("example.com.") is False
    assert state.flagged_count == 0


def test_queue_proxy_flags_on_fifth_occurrence_within_window():
    state = R7QueueProxyState(window_size=100, threshold=5)
    for i in range(4):
        state.observe("example.com.")
    assert state.observe("example.com.") is True
    assert state.flagged_count == 1


def test_queue_proxy_ignores_occurrences_that_scrolled_out_of_window():
    state = R7QueueProxyState(window_size=10, threshold=5)
    for _ in range(4):
        state.observe("example.com.")
    # push 10 unrelated packets so all 4 prior "example.com." entries scroll out of a
    # window_size=10 queue
    for i in range(10):
        state.observe(f"other-{i}.example.com.")
    assert state.observe("example.com.") is False  # only 1 in the current window


def test_queue_proxy_different_qnames_counted_independently():
    state = R7QueueProxyState(window_size=100, threshold=5)
    for _ in range(4):
        state.observe("a.example.com.")
    for _ in range(4):
        state.observe("b.example.com.")
    assert state.observe("a.example.com.") is True  # 5th "a" within the last 100
    assert state.observe("b.example.com.") is True  # 5th "b" within the last 100


def test_queue_proxy_total_benign_counts_every_observation():
    state = R7QueueProxyState()
    for i in range(7):
        state.observe(f"host{i}.example.com.")
    assert state.total_benign == 7


def test_queue_proxy_summary_fraction_matches_flagged_count():
    state = R7QueueProxyState(window_size=100, threshold=5)
    for _ in range(5):
        state.observe("flood.example.com.")
    summary = state.to_summary()
    assert summary["flagged_count"] == 1
    assert summary["total_benign"] == 5
    assert summary["fraction"] == 1 / 5
