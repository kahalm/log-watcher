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
    sig = "abc123"
    st = {}
    assert not state.in_cooldown(st, sig, 3600, now=1000)
    st = state.record(st, sig, now=1000)
    assert state.in_cooldown(st, sig, 3600, now=1500)       # innerhalb Cooldown
    assert not state.in_cooldown(st, sig, 3600, now=5000)    # nach Cooldown


def test_record_prunes_old():
    st = {}
    st = state.record(st, "old", now=0.0)               # uralt
    st = state.record(st, "fresh", now=40 * 86400.0)    # 40 Tage später
    assert "old" not in st["alerts"]
    assert "fresh" in st["alerts"]


def test_save_load_roundtrip(tmp_path):
    p = str(tmp_path / "state.json")
    st = state.record({}, "sig1", now=123.0)
    state.save_state(p, st)
    loaded = state.load_state(p)
    assert loaded.get("alerts", {}).get("sig1") == 123.0


def test_load_missing_returns_empty(tmp_path):
    assert state.load_state(str(tmp_path / "nope.json")) == {}
