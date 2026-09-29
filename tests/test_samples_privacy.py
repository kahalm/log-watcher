"""Beispielzeilen an Anthropic ohne gerenderte Werte; Heartbeat davon entkoppelt (Fund S5-005).

Vorher gingen per Default bis zu 5 GERENDERTE Fehlerzeilen (Feld 'message') an Anthropic — der
Scrub entfernt E-Mails/IPs/Tokens, aber keine Benutzernamen ('cmd_announce fehlgeschlagen für
<Discord-Name>'). README versprach „keine Rohlogs/PII". Der Heartbeat-Abgleich hing am selben
Feld, darum konnte der Sample-Default nicht einfach umziehen.
"""
from datetime import datetime, timezone
from unittest.mock import patch

from watcher import es_client
from watcher.config import Config
from watcher.es_client import ESClient
from watcher.main import _heartbeat_counts, run_cycle


def _now():
    return datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)


def test_defaults_send_templates_and_match_heartbeats_on_the_rendered_message(monkeypatch):
    monkeypatch.delenv("LLM_SAMPLE_FIELD", raising=False)
    monkeypatch.delenv("HEARTBEAT_FIELD", raising=False)
    cfg = Config()
    assert cfg.sample_field == ""            # leer = Template-Feld (message_field)
    assert cfg.heartbeat_field == "message"


def test_heartbeat_query_uses_its_own_field_not_the_sample_field(monkeypatch):
    monkeypatch.delenv("HEARTBEAT_FIELD", raising=False)
    cfg = Config()
    cfg.sample_field = "labels.MessageTemplate"
    cfg.heartbeat_checks = ["rookhub-api=rookhub-logs-*=Heartbeat: rookhub-api"]
    cfg.heartbeat_max_staleness_minutes = 5
    seen = []

    class _ES:
        def count(self, index, query):
            seen.append(query)
            return 3

    assert _heartbeat_counts(cfg, _ES(), _now()) == {"rookhub-api": 3}
    phrase = seen[0]["bool"]["must"][0]["match_phrase"]
    assert phrase == {"message": "Heartbeat: rookhub-api"}


class _SpikeES:
    """Fehler-Spike im aktuellen Fenster, damit der LLM-Pfad (und damit fetch_samples) läuft."""

    def __init__(self):
        self.calls = 0
        self.sample_fields = []

    def aggregate_window(self, a, b):
        self.calls += 1
        if self.calls == 1:
            return {"total": 100, "levels": {"Error": 30},
                    "error_messages": {"cmd_announce fehlgeschlagen für {User}": 30}, "per_index": {}}
        return {"total": 100, "levels": {"Error": 1},
                "error_messages": {"cmd_announce fehlgeschlagen für {User}": 1}, "per_index": {}}

    def fetch_samples(self, a, b, size, field):
        self.sample_fields.append(field)
        return ["cmd_announce fehlgeschlagen für {User}"]


def _llm_cfg(tmp_path):
    cfg = Config()
    cfg.name = "rookhub-prod"
    cfg.state_file = str(tmp_path / "state.json")
    cfg.dry_run = True
    cfg.anthropic_api_key = "sk-test"
    cfg.include_samples = True
    cfg.sample_field = ""
    cfg.message_field = "labels.MessageTemplate"
    cfg.index_alerts = False
    cfg.index_silent_window_hours = 0
    cfg.heartbeat_max_staleness_minutes = 0
    cfg.security_check = False
    cfg.linux_check = False
    return cfg


def test_samples_come_from_the_template_field_by_default(tmp_path):
    es = _SpikeES()
    verdict = {"anomalous": False, "severity": "low", "summary": "x", "llm_used": True, "llm_tokens": 1}
    with patch("watcher.main.analyzer.assess", return_value=verdict) as assess:
        run_cycle(_llm_cfg(tmp_path), es, _now())
    assert es.sample_fields == ["labels.MessageTemplate"]
    assert assess.call_args.kwargs["samples"] == ["cmd_announce fehlgeschlagen für {User}"]


def test_explicit_sample_field_still_wins(tmp_path):
    es = _SpikeES()
    cfg = _llm_cfg(tmp_path)
    cfg.sample_field = "message"
    verdict = {"anomalous": False, "severity": "low", "summary": "x", "llm_used": True, "llm_tokens": 1}
    with patch("watcher.main.analyzer.assess", return_value=verdict):
        run_cycle(cfg, es, _now())
    assert es.sample_fields == ["message"]


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_fetch_samples_reads_nested_ecs_fields(monkeypatch):
    """labels.MessageTemplate steht im _source verschachtelt — per _source.get('labels.…')
    käme nichts an; die fields-Option liefert den Wert unter dem vollen Pfad."""
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["body"] = json
        return _Resp({"hits": {"hits": [
            {"_source": {"labels": {"MessageTemplate": "Import fehlgeschlagen für {User}"}},
             "fields": {"labels.MessageTemplate": ["Import fehlgeschlagen für {User}"]}},
            {"fields": {}},
        ]}})

    monkeypatch.setattr(es_client.requests, "post", fake_post)
    out = ESClient(Config()).fetch_samples("a", "b", 5, "labels.MessageTemplate")
    assert out == ["Import fehlgeschlagen für {User}"]
    assert captured["body"]["fields"] == ["labels.MessageTemplate"]
    assert captured["body"]["_source"] is False
