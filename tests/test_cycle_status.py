"""Zyklus-Status je Target als ECS-Dokument in log-watcher-cycles-* (S5-017).

Vorher loggte der Wächter seinen Zustand nur als Klartext auf stdout; in Kibana sah man Alerts,
aber nicht, ob und wie die Zyklen liefen (Dauer, Signale, Fehler). Abschaltbar, Vorgabe aus.
"""
from datetime import datetime, timezone

from watcher import alerts, main as m
from watcher.config import Config
from watcher.es_client import ESError


def _now():
    return datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)


class _QuietES:
    """Nichts los: leere Fenster, keine Zusatzsignale."""

    def __init__(self, fail_index=False):
        self.indexed = []
        self.fail_index = fail_index

    def aggregate_window(self, a, b):
        return {"total": 100, "levels": {"Information": 100}, "error_messages": {}, "per_index": {}}

    def per_index_counts(self, a, b):
        return {}

    def count(self, index, query):
        return 3

    def security_window(self, a, b):
        return {"total_requests": 0, "suspicious": {"count": 0, "paths": {}, "ips": {}}, "by_ip": {}}

    def linux_window(self, a, b, c):
        return {"hosts": {}, "baseline_hosts": {}}

    def index_alert(self, doc, idx):
        if self.fail_index:
            raise ESError("ES HTTP 429", status=429)
        self.indexed.append((idx, doc))


class _BrokenES(_QuietES):
    def aggregate_window(self, a, b):
        raise ESError("ES nicht erreichbar: http://10.0.0.1:9200 refused", status=None)


def _cfg(tmp_path, enabled=True):
    cfg = Config()
    cfg.name = "rookhub"
    cfg.state_file = str(tmp_path / "state.json")
    cfg.dry_run = False
    cfg.discord_webhook_url = "https://discord.example/webhook"
    cfg.anthropic_api_key = None
    cfg.cycle_status_enabled = enabled
    return cfg


def test_default_is_off():
    c = Config()
    assert c.cycle_status_enabled is False
    assert c.cycle_status_index_prefix == "log-watcher-cycles"


def test_successful_cycle_writes_one_ecs_status_doc(tmp_path):
    es = _QuietES()
    results = m._run_cycles([(_cfg(tmp_path), es)], _now())
    assert results == {"rookhub": None}
    assert len(es.indexed) == 1
    idx, doc = es.indexed[0]
    assert idx == "log-watcher-cycles-2026.10"
    assert doc["@timestamp"] == "2026-10-26T12:00:00.000Z"
    assert doc["event"]["kind"] == "event"
    assert doc["event"]["dataset"] == "log-watcher.cycle"
    assert doc["event"]["outcome"] == "success"
    assert isinstance(doc["event"]["duration"], int) and doc["event"]["duration"] >= 0   # ns (ECS)
    lw = doc["log-watcher"]
    assert lw["target"] == "rookhub"
    assert lw["result"] == "quiet"
    assert lw["signals"] == 0 and lw["signal_kinds"] == []
    assert lw["window_total"] == 100
    assert lw["error"] is None
    assert doc["service"]["name"] == "log-watcher"


def test_failed_cycle_writes_failure_doc_without_es_address(tmp_path):
    es = _BrokenES()
    results = m._run_cycles([(_cfg(tmp_path), es)], _now())
    assert results["rookhub"] == "ES nicht erreichbar"
    (_, doc), = es.indexed
    assert doc["event"]["outcome"] == "failure"
    assert doc["log-watcher"]["error"] == "ES nicht erreichbar"
    assert "10.0.0.1" not in str(doc)


def test_disabled_or_dry_run_writes_nothing(tmp_path):
    es = _QuietES()
    m._run_cycles([(_cfg(tmp_path, enabled=False), es)], _now())
    cfg = _cfg(tmp_path)
    cfg.dry_run = True
    m._run_cycles([(cfg, es)], _now())
    assert es.indexed == []


def test_status_write_failure_does_not_fail_the_cycle(tmp_path, caplog):
    es = _QuietES(fail_index=True)
    assert m._run_cycles([(_cfg(tmp_path), es)], _now()) == {"rookhub": None}
    assert any("Zyklus-Status" in r.getMessage() for r in caplog.records)


def test_build_cycle_doc_counts_signal_kinds():
    cfg = Config()
    cfg.name = "x"
    doc = alerts.build_cycle_doc(cfg, _now(), 1.5,
                                 {"result": "alerted", "signals": ["error_spike", "error_spike", "fatal"],
                                  "window_total": 7}, None)
    assert doc["event"]["duration"] == 1_500_000_000
    assert doc["log-watcher"]["signals"] == 3
    assert doc["log-watcher"]["signal_kinds"] == ["error_spike", "fatal"]
    assert doc["log-watcher"]["result"] == "alerted"
