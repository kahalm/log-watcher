from watcher import state


class _S:
    def __init__(self, kind, detail):
        self.kind = kind
        self.detail = detail
        self.severity_hint = "medium"


def test_signature_stable_and_distinct():
    a = [_S("error_spike", "30 Fehler")]
    b = [_S("error_spike", "30 Fehler")]
    c = [_S("error_spike", "99 Fehler")]
    assert state.signature(a) == state.signature(b)
    assert state.signature(a) != state.signature(c)


def test_cooldown_window():
    st = {}
    assert not state.in_cooldown(st, "t", "sig", 3600, now=1000)
    state.record_alert(st, "t", "sig", now=1000)
    assert state.in_cooldown(st, "t", "sig", 3600, now=1500)
    assert not state.in_cooldown(st, "t", "sig", 3600, now=5000)


def test_cooldown_is_per_target():
    st = {}
    state.record_alert(st, "a", "sig", now=1000)
    assert state.in_cooldown(st, "a", "sig", 3600, now=1100)
    assert not state.in_cooldown(st, "b", "sig", 3600, now=1100)


def test_first_seen_fingerprints():
    st = {}
    assert state.known_fingerprints(st, "t") == set()
    state.record_fingerprints(st, "t", {"fp1", "fp2"}, now=1000)
    assert state.known_fingerprints(st, "t") == {"fp1", "fp2"}


def test_verdict_cache_ttl():
    st = {}
    assert state.get_cached_verdict(st, "t", "sig", 3600, now=1000) is None
    state.put_verdict(st, "t", "sig", {"anomalous": True}, now=1000)
    assert state.get_cached_verdict(st, "t", "sig", 3600, now=1500) == {"anomalous": True}
    assert state.get_cached_verdict(st, "t", "sig", 3600, now=5000) is None


def test_llm_budget_per_day():
    st = {}
    assert state.llm_calls_remaining(st, "2026-06-01", 3) == 3
    state.record_llm_call(st, "2026-06-01", 100)
    state.record_llm_call(st, "2026-06-01", 50)
    assert state.llm_calls_remaining(st, "2026-06-01", 3) == 1
    assert state.llm_calls_remaining(st, "2026-06-02", 3) == 3  # neuer Tag


def test_save_load_roundtrip(tmp_path):
    p = str(tmp_path / "state.json")
    st = state.record_alert({}, "t", "sig1", now=123.0)
    state.save_state(p, st)
    loaded = state.load_state(p)
    assert loaded["targets"]["t"]["alerts"]["sig1"] == 123.0


def test_load_missing_returns_empty(tmp_path):
    assert state.load_state(str(tmp_path / "nope.json")) == {}
