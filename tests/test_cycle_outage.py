"""ES weg = Wächter blind — das darf nicht als „alles in Ordnung" durchgehen (Fund S5-001).

Szenario: rookhub-es ist über Nacht weg. Jeder Zyklus: aggregate_window wirft ESError, die
Hauptschleife loggte das nur. Um 08:00 UTC ging trotzdem „Zwei Uhr und alles in Ordnung ...
Keine Auffälligkeiten in den letzten 24 h" nach Discord — obwohl keine einzige Prüfung lief.
"""
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import requests
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.exceptions import MaxRetryError, NewConnectionError

from watcher import state
from watcher.config import Config
from watcher.es_client import ESClient, ESError
from watcher.main import (_cycle_failure_reason, _maybe_alliswell, _maybe_cycle_outage_warning,
                          _record_cycle_results, _run_cycles)


def _now(hour=8, minute=0):
    return datetime(2026, 9, 29, hour, minute, 0, tzinfo=timezone.utc)


def _cfg(name, es_url="http://10.24.13.6:9200", tmp_path=None):
    cfg = Config()
    cfg.name = name
    cfg.es_url = es_url
    cfg.discord_webhook_url = "https://discord.example/webhook"
    cfg.state_file = str(tmp_path / "state.json") if tmp_path is not None else "/tmp/test_cycle_outage.json"
    cfg.dry_run = False
    cfg.alliswell_enabled = True
    cfg.alliswell_hour = 8
    cfg.es_outage_notice_hours = 24
    cfg.anthropic_api_key = None
    cfg.index_alerts = False
    cfg.index_silent_window_hours = 0
    cfg.heartbeat_max_staleness_minutes = 0
    cfg.security_check = False
    cfg.linux_check = False
    return cfg


class _DeadES:
    def aggregate_window(self, a, b):
        raise ESError("ES nicht erreichbar: Connection refused", status=None)


class _QuietES:
    def aggregate_window(self, a, b):
        return {"total": 100, "levels": {"Information": 100}, "error_messages": {}, "per_index": {}}


def _cycle(clients, st, now, glob):
    """Ein Durchlauf wie in main(): Zyklen, Ergebnis festhalten, Warnung, All-is-well."""
    results = _run_cycles(clients, now)
    _record_cycle_results(glob, st, results, now)
    targets = [c for c, _ in clients]
    _maybe_cycle_outage_warning(glob, targets, st, now)
    _maybe_alliswell(glob, targets, st, now)
    return results


def _texts(post):
    return [c.args[1] for c in post.call_args_list]


def test_dead_es_suppresses_alliswell(tmp_path):
    glob = _cfg("rookhub-prod", tmp_path=tmp_path)
    clients = [(glob, _DeadES())]
    st = {"targets": {"rookhub-prod": {"last_ok": _now(0).timestamp() - 3600}}}
    with patch("watcher.main.discord_notify.post_text") as post:
        results = _cycle(clients, st, _now(8), glob)

    assert "nicht erreichbar" in results["rookhub-prod"]
    assert not any("alles in Ordnung" in t for t in _texts(post))
    assert "last_alliswell" not in st         # der Tag bleibt offen


def test_unexpected_exception_counts_as_failed_cycle(tmp_path):
    glob = _cfg("rookhub-prod", tmp_path=tmp_path)

    class _Broken:
        def aggregate_window(self, a, b):
            raise KeyError("levels")

    results = _run_cycles([(glob, _Broken())], _now(8))
    assert results["rookhub-prod"].startswith("Unerwarteter Fehler: KeyError")


def test_single_failed_cycle_blocks_alliswell_but_does_not_warn(tmp_path):
    glob = _cfg("rookhub-prod", tmp_path=tmp_path)
    st = {}
    with patch("watcher.main.discord_notify.post_text") as post:
        _cycle([(glob, _DeadES())], st, _now(8), glob)
    post.assert_not_called()                  # ein Schluckauf ist noch keine Warnung wert
    assert state.cycle_outage(st, "rookhub-prod")["cycles"] == 1


def test_second_failed_cycle_warns_once_for_all_targets_of_the_same_es(tmp_path):
    names = ["rookhub-prod", "rookhub-dev", "piratechess-prod", "lernkompass-prod"]
    cfgs = [_cfg(n, tmp_path=tmp_path) for n in names] + [_cfg("extern", es_url="http://es-b:9200",
                                                               tmp_path=tmp_path)]
    glob = cfgs[0]
    clients = [(c, _DeadES()) for c in cfgs]
    st = {}
    with patch("watcher.main.discord_notify.post_text") as post:
        _cycle(clients, st, _now(7, 50), glob)
        _cycle(clients, st, _now(8, 0), glob)
        _cycle(clients, st, _now(8, 10), glob)    # kein zweites Mal

    texts = _texts(post)
    assert len(texts) == 1                    # EINE Sammelmeldung statt fünf
    msg = texts[0]
    assert "blind" in msg and "⚠️" in msg
    lines = [l for l in msg.splitlines() if l.startswith("> ")]
    assert len(lines) == 2                    # eine Zeile je Elasticsearch
    assert all(n in lines[0] for n in names) and "extern" in lines[1]
    assert "seit 10 min" in lines[0]
    assert not any("alles in Ordnung" in t for t in texts)
    for c in cfgs:
        assert state.cycle_outage(st, c.name)["notified_at"] == _now(8, 0).timestamp()


def test_warning_repeats_only_after_the_configured_interval(tmp_path):
    glob = _cfg("rookhub-prod", tmp_path=tmp_path)
    clients = [(glob, _DeadES())]
    st = {}
    with patch("watcher.main.discord_notify.post_text") as post:
        _cycle(clients, st, _now(7, 50), glob)
        _cycle(clients, st, _now(8, 0), glob)
        _cycle(clients, st, _now(20, 0), glob)                    # 12 h später: noch nicht
        assert post.call_count == 1
        _cycle(clients, st, _now(8, 0) + timedelta(hours=25), glob)
        assert post.call_count == 2


def test_failed_discord_post_is_retried_next_cycle(tmp_path):
    glob = _cfg("rookhub-prod", tmp_path=tmp_path)
    clients = [(glob, _DeadES())]
    st = {}
    with patch("watcher.main.discord_notify.post_text", side_effect=RuntimeError("Discord weg")):
        _cycle(clients, st, _now(7, 50), glob)
        _cycle(clients, st, _now(8, 0), glob)
    assert state.cycle_outage(st, "rookhub-prod").get("notified_at") is None


def test_recovery_is_announced_and_alliswell_returns(tmp_path):
    glob = _cfg("rookhub-prod", tmp_path=tmp_path)
    st = {}
    with patch("watcher.main.discord_notify.post_text") as post:
        _cycle([(glob, _DeadES())], st, _now(7, 50), glob)
        _cycle([(glob, _DeadES())], st, _now(8, 0), glob)      # Warnung
        _cycle([(glob, _QuietES())], st, _now(8, 10), glob)    # Entwarnung + All-is-well
        _cycle([(glob, _QuietES())], st, _now(8, 20), glob)    # nichts mehr

    texts = _texts(post)
    assert len(texts) == 3
    assert "⚠️" in texts[0]
    assert "✅" in texts[1] and "rookhub-prod" in texts[1]
    assert "alles in Ordnung" in texts[2]
    assert state.cycle_outage(st, "rookhub-prod") is None
    assert "cycle_recovered" not in st


def test_blip_without_warning_has_no_recovery_message(tmp_path):
    glob = _cfg("rookhub-prod", tmp_path=tmp_path)
    st = {}
    with patch("watcher.main.discord_notify.post_text") as post:
        _cycle([(glob, _DeadES())], st, _now(7, 0), glob)
        _cycle([(glob, _QuietES())], st, _now(7, 10), glob)
    post.assert_not_called()


def test_alliswell_needs_a_successful_check_within_24h(tmp_path):
    glob = _cfg("rookhub-prod", tmp_path=tmp_path)
    now = _now(8)
    with patch("watcher.main.discord_notify.post_text") as post, \
         patch("watcher.main.state.save_state"):
        _maybe_alliswell(glob, [glob], {}, now)                                    # nie geprüft
        _maybe_alliswell(glob, [glob], {"targets": {"rookhub-prod": {
            "last_ok": now.timestamp() - 86401}}}, now)                            # zu lange her
        post.assert_not_called()
        _maybe_alliswell(glob, [glob], {"targets": {"rookhub-prod": {
            "last_ok": now.timestamp() - 600}}}, now)
        post.assert_called_once()


# --- Keine ES-Adresse in Discord (Nacharbeit S5-005) -----------------------------------------
# str(ESError) trägt bei einem Verbindungsfehler die requests-Meldung samt
# „HTTPConnectionPool(host='10.24.13.6', port=9200) … url: /…/_search". Die übersteht
# escape_markdown und [:200] und stand damit in der Warnung „Log-Wächter blind".

def _real_connection_error():
    """Genau das, was requests bei abgelehnter Verbindung zur ES wirft."""
    pool = HTTPConnectionPool("10.24.13.6", 9200)
    cause = NewConnectionError(
        None, "Failed to establish a new connection: [Errno 111] Connection refused")
    return requests.exceptions.ConnectionError(
        MaxRetryError(pool, "/rookhub-logs-*,piratechess-logs-*/_search", cause))


def test_blind_warning_does_not_post_the_es_address(tmp_path, caplog):
    glob = _cfg("rookhub-prod", tmp_path=tmp_path)
    err = _real_connection_error()
    assert "10.24.13.6" in str(err)            # Vorbedingung: die Meldung trägt den Host
    clients = [(glob, ESClient(glob))]          # echter ES-Client -> echter ESError-Text
    st = {}
    with patch("watcher.es_client.requests.post", side_effect=err), \
         patch("watcher.main.discord_notify.post_text") as post, \
         caplog.at_level(logging.ERROR, logger="watcher.main"):
        _cycle(clients, st, _now(7, 50), glob)
        _cycle(clients, st, _now(8, 0), glob)

    texts = _texts(post)
    assert len(texts) == 1 and "blind" in texts[0]
    msg = texts[0]
    assert "ES nicht erreichbar (ConnectionError)" in msg
    for leak in ("10.24.13.6", "9200", "HTTPConnectionPool", "_search", "rookhub-logs"):
        assert leak not in msg, leak
    # Auch der State (Quelle der Warnung) trägt keine Adresse ...
    assert "10.24.13.6" not in state.cycle_outage(st, "rookhub-prod")["reason"]
    # ... der volle Text bleibt im Log zur Diagnose.
    assert any("10.24.13.6" in r.getMessage() for r in caplog.records)


def test_blind_warning_names_http_status_without_response_body(tmp_path):
    glob = _cfg("rookhub-prod", tmp_path=tmp_path)
    resp = requests.Response()
    resp.status_code = 503
    resp.reason = "Service Unavailable"
    resp.url = "http://10.24.13.6:9200/rookhub-logs-*/_search"
    resp._content = b'{"error":{"reason":"node 10.24.13.6:9300 not available"},"status":503}'
    clients = [(glob, ESClient(glob))]
    st = {}
    with patch("watcher.es_client.requests.post", return_value=resp), \
         patch("watcher.main.discord_notify.post_text") as post:
        _cycle(clients, st, _now(7, 50), glob)
        _cycle(clients, st, _now(8, 0), glob)

    msg = _texts(post)[0]
    assert "ES HTTP 503" in msg
    assert "10.24.13.6" not in msg and "not available" not in msg


def test_failure_reason_never_carries_the_exception_text():
    conn = ESError("ES nicht erreichbar: HTTPConnectionPool(host='10.24.13.6', port=9200)")
    try:
        raise conn from requests.exceptions.ReadTimeout("10.24.13.6:9200 read timed out")
    except ESError as e:
        assert _cycle_failure_reason(e) == "ES nicht erreichbar (ReadTimeout)"
    try:
        raise ESError("ES _count: unlesbare Antwort: …") from ValueError("Expecting value")
    except ESError as e:
        assert _cycle_failure_reason(e) == "ES-Fehler (ValueError)"
    assert _cycle_failure_reason(ESError("ES HTTP 400: {…}", status=400)) == "ES HTTP 400"
    assert _cycle_failure_reason(ESError("ES nicht erreichbar: x")) == "ES nicht erreichbar"
    assert (_cycle_failure_reason(RuntimeError("connect to 10.24.13.6:9200 failed"))
            == "Unerwarteter Fehler: RuntimeError")
