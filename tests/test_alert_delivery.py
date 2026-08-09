"""Cooldown darf erst greifen, wenn ein Alert wirklich zugestellt wurde."""
from datetime import datetime, timezone
from unittest.mock import patch

from watcher.config import Config
from watcher.main import run_cycle, _maybe_digest


def _now():
    return datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)


class _FakeES:
    """Aktuelles Fenster mit Fehler-Spike, ruhiges Vorfenster (1. Aufruf = current)."""

    def __init__(self):
        self.calls = 0

    def aggregate_window(self, a, b):
        self.calls += 1
        if self.calls == 1:
            return {"total": 100, "levels": {"Error": 30}, "error_messages": {"boom": 30}, "per_index": {}}
        return {"total": 100, "levels": {"Error": 1}, "error_messages": {"boom": 1}, "per_index": {}}

    def count(self, index, query):
        return 7


def _cfg(tmp_path):
    cfg = Config()
    cfg.name = "t"
    cfg.state_file = str(tmp_path / "state.json")
    cfg.dry_run = False
    cfg.smtp_host = None
    cfg.discord_webhook_url = "https://discord.example/webhook"
    cfg.anthropic_api_key = None          # regelbasiert -> anomalous=True
    cfg.index_alerts = False
    cfg.index_silent_window_hours = 0
    cfg.heartbeat_max_staleness_minutes = 0
    cfg.security_check = False
    cfg.linux_check = False
    return cfg


def _alerts(cfg):
    from watcher import state
    return state.load_state(cfg.state_file).get("targets", {}).get("t", {}).get("alerts", {})


def test_cooldown_recorded_after_successful_delivery(tmp_path):
    cfg = _cfg(tmp_path)
    with patch("watcher.main.discord_notify.post", return_value=204):
        run_cycle(cfg, _FakeES(), _now())
    assert len(_alerts(cfg)) == 1


def test_no_cooldown_when_all_channels_fail(tmp_path):
    cfg = _cfg(tmp_path)
    with patch("watcher.main.discord_notify.post", side_effect=OSError("Cloudflare 403")):
        run_cycle(cfg, _FakeES(), _now())
    # Niemand wurde benachrichtigt -> der nächste Zyklus muss es erneut versuchen dürfen.
    assert _alerts(cfg) == {}


def test_failed_delivery_still_persists_fingerprints(tmp_path):
    cfg = _cfg(tmp_path)
    from watcher import state
    with patch("watcher.main.discord_notify.post", side_effect=OSError("boom")):
        run_cycle(cfg, _FakeES(), _now())
    assert state.load_state(cfg.state_file)["targets"]["t"]["seen"]


class _EvilES:
    """Fehlermeldungen mit Markdown/Mention — so kämen sie roh aus ES."""

    def aggregate_window(self, a, b):
        return {"total": 10, "levels": {"Error": 5},
                "error_messages": {"``` @everyone [klick](https://evil.example)": 5}, "per_index": {}}

    def count(self, index, query):
        return 1


def test_digest_discord_dead_mentions_and_intact_fence(tmp_path, monkeypatch):
    """Digest-Pfad: das Wire-Payload muss allowed_mentions {parse: []} tragen (@everyone tot),
    und Backticks aus ES-Fehlermeldungen dürfen den Code-Zaun nicht sprengen."""
    import json
    from watcher import discord_notify

    glob = _cfg(tmp_path)
    glob.digest_enabled = True
    glob.digest_hour = 0
    captured = {}

    class FakeResp:
        status = 204
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=None):
        captured["data"] = req.data
        return FakeResp()

    monkeypatch.setattr(discord_notify.urllib.request, "urlopen", fake_urlopen)
    with patch("watcher.main.state.save_state"):
        _maybe_digest(glob, [(glob, _EvilES())], {}, _now())

    payload = json.loads(captured["data"])
    assert payload["allowed_mentions"] == {"parse": []}
    # Nur die zwei Zaun-Markierungen selbst — die Backticks der Fehlermeldung sind neutralisiert.
    assert payload["content"].count("`") == 6


def test_digest_marker_only_after_successful_send(tmp_path):
    glob = _cfg(tmp_path)
    glob.digest_enabled = True
    glob.digest_hour = 0
    glob.digest_period_days = 1
    st = {}
    with patch("watcher.main.discord_notify.post_text", side_effect=OSError("down")), \
         patch("watcher.main.state.save_state"):
        _maybe_digest(glob, [(glob, _FakeES())], st, _now())
    assert "last_digest" not in st

    with patch("watcher.main.discord_notify.post_text", return_value=204), \
         patch("watcher.main.state.save_state"):
        _maybe_digest(glob, [(glob, _FakeES())], st, _now())
    assert st["last_digest"] == "2026-06-06"
