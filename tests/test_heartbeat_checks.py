"""Heartbeat-Prüfung über das strukturierte Feld labels.HeartbeatService (Fund S5-008).

Vorher suchte der Watcher den Bot-Heartbeat per match_phrase 'ClientLog heartbeat_bot' in der
gerenderten Nachricht. /api/client-log ist anonym: wer alle paar Minuten {"kind":"heartbeat_bot"}
schickt (oder einen Pfad mit dem Text anfragt), hielt einen toten schach-bot „lebendig" —
heartbeat_missing feuerte nie. Das Feld HeartbeatService setzt nur das Heartbeat-Template der
Dienste ('Heartbeat: {HeartbeatService} …'), kein Freitext.
"""
import logging
from datetime import datetime, timezone

from watcher import main as watcher_main
from watcher import rules
from watcher.config import Config
from watcher.main import _heartbeat_counts


def _now():
    return datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)


def _get(doc: dict, dotted: str):
    cur = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


class _DocsES:
    """Winziges ES-Double: wertet term/match_phrase der Heartbeat-Abfrage gegen feste Dokumente aus
    (Zeitfenster ignoriert — alle Dokumente liegen im Fenster)."""

    def __init__(self, docs):
        self.docs = docs
        self.queries = []

    def count(self, index, query):
        self.queries.append((index, query))
        n = 0
        for doc in self.docs:
            ok = True
            for clause in query["bool"]["must"]:
                if "term" in clause:
                    (field, value), = clause["term"].items()
                    ok &= _get(doc, field) == value
                elif "match_phrase" in clause:
                    (field, phrase), = clause["match_phrase"].items()
                    ok &= phrase.lower() in str(_get(doc, field) or "").lower()
            n += ok
        return n


# Anonym gefälschte Zeilen: ClientLog mit kind=heartbeat_bot und ein Request-Log mit dem Text im Pfad.
_FORGED = [
    {"message": "ClientLog heartbeat_bot: alive (url= user= ua=curl/8)",
     "labels": {"ClientLogKind": "heartbeat_bot", "MessageTemplate": "ClientLog {ClientLogKind}: …"}},
    {"message": "HTTP GET /ClientLog heartbeat_bot responded 404 in 1.2 ms",
     "url": {"path": "/ClientLog heartbeat_bot"}, "http": {"response": {"status_code": 404}}},
    {"message": "HTTP GET /Heartbeat: rookhub-api responded 404 in 0.9 ms",
     "url": {"path": "/Heartbeat: rookhub-api"}, "http": {"response": {"status_code": 404}}},
]

# Echte Heartbeat-Zeile (rookhub HeartbeatService.cs, ECS-Sink: String-Property -> labels.*).
_REAL_API = {"message": "Heartbeat: rookhub-api healthy db=True uptime=60s",
             "labels": {"HeartbeatService": "rookhub-api", "HeartbeatStatus": "healthy"},
             "log": {"logger": "RookHub.Api.Services.HeartbeatService"}}


def _cfg(monkeypatch, **over):
    for key in ("HEARTBEAT_CHECKS", "HEARTBEAT_SERVICE_FIELD", "HEARTBEAT_FIELD"):
        monkeypatch.delenv(key, raising=False)
    cfg = Config()
    cfg.heartbeat_max_staleness_minutes = 5
    for k, v in over.items():
        setattr(cfg, k, v)
    return cfg


def test_defaults_check_the_structured_service_field(monkeypatch):
    cfg = _cfg(monkeypatch)
    assert cfg.heartbeat_checks == ["rookhub-api=rookhub-logs-*",
                                    "rookhub-crawler=crawler-logs-*",
                                    "schach-bot=rookhub-logs-*"]
    assert cfg.heartbeat_service_field == "labels.HeartbeatService"

    es = _DocsES([])
    _heartbeat_counts(cfg, es, _now())
    assert [(idx, q["bool"]["must"][0]) for idx, q in es.queries] == [
        ("rookhub-logs-*", {"term": {"labels.HeartbeatService": "rookhub-api"}}),
        ("crawler-logs-*", {"term": {"labels.HeartbeatService": "rookhub-crawler"}}),
        ("rookhub-logs-*", {"term": {"labels.HeartbeatService": "schach-bot"}}),
    ]
    # Zeitfenster bleibt Teil jeder Abfrage.
    assert all("range" in q["bool"]["must"][1] for _, q in es.queries)


def test_forged_heartbeat_lines_do_not_keep_a_dead_service_alive(monkeypatch):
    """Der Fall aus dem Fund: schach-bot ist tot, anonyme Zeilen mit dem Heartbeat-Text laufen weiter."""
    cfg = _cfg(monkeypatch)
    es = _DocsES(_FORGED + [_REAL_API])
    counts = _heartbeat_counts(cfg, es, _now())
    assert counts == {"rookhub-api": 1, "rookhub-crawler": 0, "schach-bot": 0}
    missing = {s.detail.split("'")[1] for s in rules.evaluate_heartbeats(counts, cfg)}
    assert missing == {"rookhub-crawler", "schach-bot"}


def test_signed_bot_heartbeat_counts(monkeypatch):
    """Vertrag mit rookhub (POST /api/bot/heartbeat): gleiche Property HeartbeatService = schach-bot."""
    cfg = _cfg(monkeypatch)
    bot = {"message": "Heartbeat: schach-bot healthy",
           "labels": {"HeartbeatService": "schach-bot"},
           "log": {"logger": "RookHub.Api.Controllers.BotHeartbeatController"}}
    counts = _heartbeat_counts(cfg, _DocsES([bot, _REAL_API]), _now())
    assert counts["schach-bot"] == 1 and counts["rookhub-api"] == 1


def test_legacy_phrase_spec_still_works_and_warns_once(monkeypatch, caplog):
    """Prod-Konfig nutzt bis zur Umstellung die Altform — sie muss unverändert zählen."""
    monkeypatch.setattr(watcher_main, "_legacy_heartbeat_warned", set())
    cfg = _cfg(monkeypatch, heartbeat_checks=[
        "schach-bot=rookhub-logs-*=ClientLog heartbeat_bot",
        "rookhub-api=rookhub-logs-*",
    ])
    es = _DocsES(_FORGED + [_REAL_API])
    with caplog.at_level(logging.WARNING, logger="log-watcher"):
        first = _heartbeat_counts(cfg, es, _now())
        _heartbeat_counts(cfg, es, _now())
    assert first == {"schach-bot": 2, "rookhub-api": 1}
    assert es.queries[0][1]["bool"]["must"][0] == {"match_phrase": {"message": "ClientLog heartbeat_bot"}}
    assert es.queries[1][1]["bool"]["must"][0] == {"term": {"labels.HeartbeatService": "rookhub-api"}}
    legacy_warnings = [r for r in caplog.records if "Freitext" in r.getMessage()]
    assert len(legacy_warnings) == 1                     # einmal je Angabe, nicht je Zyklus
    assert "schach-bot=rookhub-logs-*" in legacy_warnings[0].getMessage()


def test_service_field_is_configurable(monkeypatch):
    monkeypatch.setenv("HEARTBEAT_SERVICE_FIELD", "metadata.HeartbeatService")
    monkeypatch.delenv("HEARTBEAT_CHECKS", raising=False)
    cfg = Config()
    cfg.heartbeat_max_staleness_minutes = 5
    cfg.heartbeat_checks = ["rookhub-api=rookhub-logs-*"]
    es = _DocsES([])
    _heartbeat_counts(cfg, es, _now())
    assert es.queries[0][1]["bool"]["must"][0] == {"term": {"metadata.HeartbeatService": "rookhub-api"}}


def test_invalid_specs_are_skipped(monkeypatch):
    cfg = _cfg(monkeypatch, heartbeat_checks=["nur-name", "=rookhub-logs-*", "rookhub-api=", "a=b="])
    es = _DocsES([])
    assert _heartbeat_counts(cfg, es, _now()) == {}
    assert es.queries == []
