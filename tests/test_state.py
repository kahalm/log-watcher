from watcher import state


class _S:
    def __init__(self, kind, detail):
        self.kind = kind
        self.detail = detail
        self.severity_hint = "medium"


def test_signature_stable_and_distinct():
    a = [_S("error_spike", "30 Fehler")]
    b = [_S("error_spike", "30 Fehler")]
    c = [_S("warn_spike", "30 Fehler")]
    assert state.signature(a) == state.signature(b)
    assert state.signature(a) != state.signature(c)  # andere Art -> andere Signatur


def test_signature_ignores_volatile_counts():
    # Derselbe anhaltende Vorfall darf pro Zyklus KEINE neue Signatur bekommen, sonst
    # greifen Cooldown und Verdict-Cache nie.
    a = [_S("error_spike", "30 Fehler im Fenster (Vorfenster: 4, Schwelle Faktor 3.0).")]
    b = [_S("error_spike", "99 Fehler im Fenster (Vorfenster: 7, Schwelle Faktor 3.0).")]
    assert state.signature(a) == state.signature(b)


def test_signature_keeps_names_distinct():
    # Namen (Dienst/Index/Host) müssen unterscheidbar bleiben — sonst dedupt ein toter
    # Dienst den nächsten weg.
    a = [_S("heartbeat_missing", "Kein Heartbeat von 'rookhub-api' in den letzten 5 min")]
    b = [_S("heartbeat_missing", "Kein Heartbeat von 'schach-bot' in den letzten 5 min")]
    c = [_S("index_silent", "Index 'vm1-logs': 0 Logs")]
    d = [_S("index_silent", "Index 'vm2-logs': 0 Logs")]
    # Bindestrich-/Punkt-Namen: '\b' allein hätte "vm-01"/"vm-02" und "logs-2"/"logs-3"
    # zusammenfallen lassen — genau die Hosts/Indizes, die unterscheidbar bleiben müssen.
    e = [_S("linux_host_silent", "Host 'vm-01' meldet nichts mehr")]
    f = [_S("linux_host_silent", "Host 'vm-02' meldet nichts mehr")]
    g = [_S("index_silent", "Index 'logs-2': 0 Logs")]
    h = [_S("index_silent", "Index 'logs-3': 0 Logs")]
    # Verschiedene Angreifer-IPs dürfen sich NICHT wegdedupen (sonst erbt der zweite den
    # 12h-Cooldown und das gecachte Verdict des ersten).
    i = [_S("api_scan", "IP 45.9.1.2: 300 4xx über 40 Pfade")]
    j = [_S("api_scan", "IP 203.0.113.7: 512 4xx über 61 Pfade")]
    assert state.signature(a) != state.signature(b)
    assert state.signature(c) != state.signature(d)
    assert state.signature(e) != state.signature(f)
    assert state.signature(g) != state.signature(h)
    assert state.signature(i) != state.signature(j)
    # Reine Zähler-Schwankungen desselben Vorfalls bleiben EINE Signatur (Cooldown greift).
    k = [_S("api_scan", "IP 45.9.1.2: 411 4xx über 52 Pfade")]
    assert state.signature(i) == state.signature(k)
    # IPv6 ebenso: die Ziffernblöcke stecken zwischen Doppelpunkten und dürfen nicht als
    # "volatile Zähler" normalisiert werden, sonst dedupen sich zwei Angreifer gegenseitig weg.
    v6a = [_S("api_scan", "IP 2001:db8::42: 300 4xx über 40 Pfade")]
    v6b = [_S("api_scan", "IP 2001:db8::99: 512 4xx über 61 Pfade")]
    assert state.signature(v6a) != state.signature(v6b)
    v6c = [_S("api_scan", "IP 2001:db8::42: 377 4xx über 44 Pfade")]
    assert state.signature(v6a) == state.signature(v6c)


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
