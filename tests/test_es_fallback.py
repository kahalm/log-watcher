from watcher.config import Config
from watcher import es_client
from watcher.es_client import ESClient, ESError


def _client():
    return ESClient(Config())


def test_falls_back_to_levels_only_on_4xx_for_message_agg():
    c = _client()
    calls = []

    def fake_search(body):
        calls.append(body)
        # Erster (voller) Body hat die errors/top_messages-Aggregation -> simuliere 400.
        if "errors" in body.get("aggs", {}):
            raise ESError("illegal_argument: field not aggregatable", status=400)
        return {"hits": {"total": {"value": 42}},
                "aggregations": {"by_level": {"buckets": [{"key": "Error", "doc_count": 7}]}}}

    c._search = fake_search
    out = c.aggregate_window("a", "b")
    assert out["total"] == 42
    assert out["levels"]["Error"] == 7
    assert out["error_messages"] == {}          # message-Agg wurde ausgelassen
    assert len(calls) == 2                        # voll -> levels-only


def test_falls_back_to_total_only_when_level_field_bad():
    c = _client()

    def fake_search(body):
        if "aggs" in body:
            raise ESError("illegal_argument: level field", status=400)
        return {"hits": {"total": {"value": 5}}}

    c._search = fake_search
    out = c.aggregate_window("a", "b")
    assert out["total"] == 5
    assert out["levels"] == {}


def test_connection_error_is_not_swallowed():
    c = _client()

    def fake_search(body):
        raise ESError("ES nicht erreichbar", status=None)

    c._search = fake_search
    try:
        c.aggregate_window("a", "b")
        assert False, "ESError erwartet"
    except ESError as e:
        assert e.status is None


def test_server_error_is_not_swallowed():
    c = _client()

    def fake_search(body):
        raise ESError("ES HTTP 503", status=503)

    c._search = fake_search
    try:
        c.aggregate_window("a", "b")
        assert False, "ESError erwartet"
    except ESError as e:
        assert e.status == 503


# ── count(): Verbindungsfehler dürfen nicht als "0 Heartbeats" durchgehen ──

class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload or {"count": 5}

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_count_returns_value(monkeypatch):
    monkeypatch.setattr(es_client.requests, "post", lambda *a, **k: _Resp())
    assert _client().count("idx-*", {"match_all": {}}) == 5


def test_count_missing_index_is_zero(monkeypatch):
    monkeypatch.setattr(es_client.requests, "post", lambda *a, **k: _Resp(status=404))
    assert _client().count("nope-*", {"match_all": {}}) == 0


def test_count_connection_error_raises(monkeypatch):
    import requests

    def boom(*a, **k):
        raise requests.ConnectionError("timeout")

    monkeypatch.setattr(es_client.requests, "post", boom)
    try:
        _client().count("idx-*", {"match_all": {}})
        assert False, "ESError erwartet — sonst meldet die Heartbeat-Prüfung alle Dienste als tot"
    except ESError as e:
        assert e.status is None


# ── Hinweis an der richtigen Stufe (Fund S5-006) ──
# Früher hing der Hinweis an der Folgestufe: scheiterte nur die volle Aggregation
# (message_field als text gemappt -> 400), fiel sie ohne jedes Log weg.

def test_failed_full_aggregation_is_logged_as_missing_top_messages(caplog):
    c = _client()

    def fake_search(body):
        if "errors" in body.get("aggs", {}):
            raise ESError("illegal_argument: field not aggregatable", status=400)
        return {"hits": {"total": {"value": 42}},
                "aggregations": {"by_level": {"buckets": [{"key": "Error", "doc_count": 7}]}}}

    c._search = fake_search
    with caplog.at_level("WARNING", logger="log-watcher"):
        c.aggregate_window("a", "b")
    msgs = [r.getMessage() for r in caplog.records]
    assert len(msgs) == 1
    assert "ohne Top-Messages" in msgs[0]


def test_failed_level_aggregation_is_logged_as_total_only(caplog):
    c = _client()

    def fake_search(body):
        if "aggs" in body:
            raise ESError("illegal_argument: level field", status=400)
        return {"hits": {"total": {"value": 5}}}

    c._search = fake_search
    with caplog.at_level("WARNING", logger="log-watcher"):
        c.aggregate_window("a", "b")
    msgs = [r.getMessage() for r in caplog.records]
    assert len(msgs) == 2
    assert "ohne Top-Messages" in msgs[0]
    assert "nur Gesamtzahl" in msgs[1]


# ── S5-002: Feld-Fallback nur bei 400; andere 4xx und eine erschöpfte Leiter sind Fehler ──
import pytest  # noqa: E402


def _always(status):
    def fake_search(body, index=None):
        raise ESError(f"ES HTTP {status}", status=status)
    return fake_search


@pytest.mark.parametrize("status", [401, 403, 404, 429])
@pytest.mark.parametrize("call", [
    lambda c: c.aggregate_window("a", "b"),
    lambda c: c.per_index_counts("a", "b"),
    lambda c: c.security_window("a", "b"),
    lambda c: c.linux_window("a", "b", "z"),
], ids=["aggregate_window", "per_index_counts", "security_window", "linux_window"])
def test_non_400_client_errors_are_not_swallowed(status, call):
    c = _client()
    c.cfg.linux_indices = ["filebeat-*"]
    calls = []

    def fake_search(body, index=None):
        calls.append(body)
        raise ESError(f"ES HTTP {status}", status=status)

    c._search = fake_search
    with pytest.raises(ESError) as ei:
        call(c)
    assert ei.value.status == status
    assert len(calls) == 1   # keine Fallback-Leiter für Auth/Not-Found/Rate-Limit


def test_exhausted_ladder_raises_instead_of_zero_window():
    c = _client()
    calls = []

    def fake_search(body, index=None):
        calls.append(body)
        raise ESError("illegal_argument", status=400)

    c._search = fake_search
    with pytest.raises(ESError) as ei:
        c.aggregate_window("a", "b")
    assert ei.value.status == 400
    assert len(calls) == 3   # voll -> levels -> total, dann Fehler statt Null-Dict


@pytest.mark.parametrize("call, empty", [
    (lambda c: c.per_index_counts("a", "b"), {}),
    (lambda c: c.security_window("a", "b"),
     {"total_requests": 0, "suspicious": {"count": 0, "paths": {}, "ips": {}}, "by_ip": {}}),
    (lambda c: c.linux_window("a", "b", "z"), {"hosts": {}, "baseline_hosts": {}}),
], ids=["per_index_counts", "security_window", "linux_window"])
def test_400_keeps_reduced_result(call, empty):
    c = _client()
    c.cfg.linux_indices = ["filebeat-*"]
    c._search = _always(400)
    assert call(c) == empty
