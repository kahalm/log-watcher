"""run_cycle zerlegt: collect_signals (gemeinsam mit replay) -> assess_cached -> deliver (Fund S5-015).

Szenario: replay kopierte die Signal-Sammlung aus run_cycle und lief bereits auseinander — der
Heartbeat-Check fehlte im Replay. Ein Regeltest über die Vergangenheit belegte damit etwas
anderes als der Echtbetrieb.
"""
import json
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from watcher import main as m, state
from watcher.config import Config
from watcher.metrics import METRICS


def _now():
    return datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)


class _RichES:
    """Jede Prüfung schlägt an: Fehler-Spike, Index-Stille, Heartbeats fehlen, Scan, SSH-Brute-Force."""

    def __init__(self):
        self.calls = []
        self._agg = 0
        self._idx = 0

    def aggregate_window(self, a, b):
        self.calls.append("aggregate_window")
        self._agg += 1
        if self._agg % 2 == 1:   # current
            return {"total": 500, "levels": {"Error": 40, "Information": 460},
                    "error_messages": {"Login fehlgeschlagen für max@example.com": 30,
                                       "Timeout bei {Url}": 10}, "per_index": {}}
        return {"total": 480, "levels": {"Error": 2, "Information": 478},
                "error_messages": {"Timeout bei {Url}": 2}, "per_index": {}}

    def per_index_counts(self, a, b):
        self.calls.append("per_index_counts")
        self._idx += 1
        return {"a-logs": 0, "b-logs": 900} if self._idx % 2 == 1 else {"a-logs": 1200, "b-logs": 880}

    def count(self, index, query):
        self.calls.append("count")
        return 0

    def security_window(self, a, b):
        self.calls.append("security_window")
        return {"total_requests": 5000, "suspicious": {"count": 0, "paths": {}, "ips": {}},
                "by_ip": {"45.9.1.2": {"total": 900, "c4xx": 600, "auth_fail": 0,
                                       "distinct_paths": 120, "distinct_paths_4xx": 110}}}

    def linux_window(self, a, b, c):
        self.calls.append("linux_window")
        return {"hosts": {"vm-01": {"total": 100, "ssh_fail": 500, "oom": 0, "disk": 0, "unit_fail": 0}},
                "baseline_hosts": {"vm-01": 90}}

    def index_alert(self, doc, idx):
        self.calls.append("index_alert")
        self.alert_doc = doc


def _cfg(tmp_path):
    cfg = Config()
    cfg.name = "t"
    cfg.state_file = str(tmp_path / "state.json")
    cfg.dry_run = False
    cfg.smtp_host = None
    cfg.discord_webhook_url = "https://discord.example/webhook"
    cfg.anthropic_api_key = None          # regelbasiert
    cfg.index_alerts = True
    cfg.scrub_pii = True
    cfg.security_check = True
    cfg.linux_check = True
    cfg.linux_indices = ["filebeat-*"]
    cfg.window_hours = 6.0
    return cfg


def _replay_kinds(caplog, cursor):
    head = f"REPLAY {m._iso(cursor)}: "
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith(head)]
    assert len(lines) == 1, lines
    return [part.split(":", 1)[0] for part in lines[0][len(head):].split(" | ")]


def test_replay_sees_the_same_signals_as_run_cycle(tmp_path, caplog):
    cfg = _cfg(tmp_path)
    with patch("watcher.main.discord_notify.post", return_value=204):
        m.run_cycle(cfg, _RichES(), _now())
    live = list(METRICS.last_cycle_signals)
    assert "heartbeat_missing" in live            # Vorbedingung: der Echtbetrieb meldet den toten Dienst

    with caplog.at_level(logging.INFO, logger="log-watcher"):
        assert m.replay(cfg, _RichES(), _now() - timedelta(hours=6), _now()) == 0
    # Frischer State: First-seen und Replay (zustandslos) sehen dieselben neuen Fehler.
    assert _replay_kinds(caplog, _now()) == live


def test_run_cycle_keeps_es_call_order_and_state_writes(tmp_path):
    cfg = _cfg(tmp_path)
    es = _RichES()
    payloads = []
    with patch("watcher.main.discord_notify.post", side_effect=lambda url, p: payloads.append(p) or 204):
        m.run_cycle(cfg, es, _now())

    assert es.calls == (["aggregate_window"] * 2 + ["per_index_counts"] * 2 + ["count"] * 3
                        + ["security_window", "linux_window", "index_alert"])
    st = state.load_state(cfg.state_file)["targets"]["t"]
    assert len(st["alerts"]) == 1 and len(st["verdicts"]) == 1 and len(st["seen"]) == 2
    sig = next(iter(st["alerts"]))
    assert es.alert_doc["signature"] == sig and es.alert_doc["emailed"] is False
    (embed,) = payloads[0]["embeds"]
    assert "Sicherheits-Alarm" in embed["title"]
    dump = json.dumps(payloads[0], ensure_ascii=False)
    assert "45.9.1.2" not in dump and "max@example.com" not in dump    # redigiert (SCRUB_PII)


def test_cooldown_return_still_persists_fingerprints(tmp_path):
    cfg = _cfg(tmp_path)
    with patch("watcher.main.discord_notify.post", return_value=204):
        m.run_cycle(cfg, _RichES(), _now())
    st = state.load_state(cfg.state_file)
    st["targets"]["t"]["seen"] = {}                 # First-seen vergessen, Cooldown bleibt
    state.save_state(cfg.state_file, st)

    suppressed = METRICS.suppressed_total
    with patch("watcher.main.discord_notify.post") as post:
        m.run_cycle(cfg, _RichES(), _now() + timedelta(minutes=10))
    post.assert_not_called()
    assert METRICS.suppressed_total == suppressed + 1
    assert len(state.load_state(cfg.state_file)["targets"]["t"]["seen"]) == 2   # vor dem Return gemerkt
