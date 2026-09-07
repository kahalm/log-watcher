"""Der Bewerter faellt aus (leeres Guthaben, abgelehnter Schluessel) — was der Waechter dann tut.

Der Fall aus dem Betrieb (2026-09-06/07): das Anthropic-Guthaben war leer, der LLM-Aufruf
antwortete mit 400, die Ausnahme flog bis in die Hauptschleife. Ergebnis: 84 Zyklen am Stueck
abgebrochen, kein Alarm — obwohl das Regel-Gate 48-mal angeschlagen hatte — und am Morgen waere
die taegliche „alles in Ordnung"-Meldung rausgegangen.
"""
import sys
import types
from datetime import datetime, timezone
from unittest.mock import patch

from watcher.config import Config
from watcher import analyzer, state
from watcher.main import _maybe_alliswell, _maybe_llm_outage_warning


class _S:
    def __init__(self, kind, detail, sev="medium"):
        self.kind = kind
        self.detail = detail
        self.severity_hint = sev


def _now(hour=8):
    return datetime(2026, 9, 7, hour, 0, 0, tzinfo=timezone.utc)


def _glob():
    cfg = Config()
    cfg.discord_webhook_url = "https://discord.example/webhook"
    cfg.state_file = "/tmp/test_llm_outage_state.json"
    cfg.dry_run = False
    cfg.name = "test"
    cfg.alliswell_enabled = True
    cfg.alliswell_hour = 8
    return cfg


def _fake_anthropic(exc: Exception):
    """Ersetzt das lazy importierte `anthropic`-Modul durch eines, dessen Aufruf scheitert."""
    mod = types.ModuleType("anthropic")

    class _Messages:
        def create(self, **_kw):
            raise exc

    class _Client:
        def __init__(self, **_kw):
            self.messages = _Messages()

    mod.Anthropic = _Client
    return mod


# ── Analyzer: der Zyklus darf nicht sterben ────────────────────────────────────────────────
def test_failed_llm_call_degrades_to_rules_instead_of_raising():
    cfg = Config()
    cfg.anthropic_api_key = "sk-test"
    signals = [_S("error_spike", "30 Fehler")]
    err = Exception("Error code: 400 - {'error': {'message': 'Your credit balance is too low "
                    "to access the Anthropic API. Please go to Plans & Billing to upgrade.'}}")
    with patch.dict(sys.modules, {"anthropic": _fake_anthropic(err)}):
        a = analyzer.assess(cfg, {"total": 10}, {"total": 5}, signals, use_llm=True)

    assert a["anomalous"] is True            # die Auffaelligkeit bleibt eine Auffaelligkeit
    assert a["llm_used"] is False
    assert a["llm_error_kind"] == "guthaben"
    assert "Guthaben" in a["llm_error"]
    assert a["severity"] == "medium"         # aus der Regel, nicht aus dem LLM


def test_classify_llm_error_names_the_thing_to_do():
    assert analyzer.classify_llm_error(Exception("credit balance is too low"))[0] == "guthaben"
    assert analyzer.classify_llm_error(Exception("authentication_error: invalid x-api-key"))[0] == "schluessel"
    assert analyzer.classify_llm_error(Exception("429 rate limit exceeded"))[0] == "drosselung"
    kind, reason = analyzer.classify_llm_error(Exception("Verbindung weg"))
    assert kind == "sonstiges" and reason == "Verbindung weg"


# ── Discord: Warnung statt Stille, kein „alles in Ordnung" ─────────────────────────────────
def test_warning_is_posted_while_the_assessor_is_down():
    glob, st = _glob(), {}
    state.set_llm_outage(st, "guthaben", "Anthropic-Guthaben erschöpft", _now(8).timestamp() - 7200)
    with patch("watcher.main.discord_notify.post_text") as post, \
         patch("watcher.main.state.save_state"):
        _maybe_llm_outage_warning(glob, st, _now(8))

    post.assert_called_once()
    msg = post.call_args[0][1]
    assert "⚠️" in msg
    assert "Guthaben" in msg
    assert "seit 2 h" in msg                       # Dauer steht drin
    assert "Plans & Billing" in msg                # und was zu tun ist


def test_warning_repeats_only_after_the_configured_interval():
    glob, st = _glob(), {}
    glob.llm_outage_notice_hours = 24
    now = _now(8)
    state.set_llm_outage(st, "guthaben", "Anthropic-Guthaben erschöpft", now.timestamp())
    with patch("watcher.main.discord_notify.post_text") as post, \
         patch("watcher.main.state.save_state"):
        _maybe_llm_outage_warning(glob, st, now)
        _maybe_llm_outage_warning(glob, st, _now(20))       # 12 h spaeter: noch nicht wieder
        assert post.call_count == 1
        _maybe_llm_outage_warning(glob, st, now.replace(day=8, hour=9))  # 25 h spaeter
        assert post.call_count == 2


def test_failed_discord_post_is_retried_next_cycle():
    glob, st = _glob(), {}
    state.set_llm_outage(st, "guthaben", "Anthropic-Guthaben erschöpft", _now(8).timestamp())
    with patch("watcher.main.discord_notify.post_text", side_effect=RuntimeError("Discord weg")), \
         patch("watcher.main.state.save_state"):
        _maybe_llm_outage_warning(glob, st, _now(8))
    assert state.llm_outage(st).get("notified_at") is None   # nicht als gemeldet verbucht


def test_alliswell_stays_silent_while_the_assessor_is_down():
    glob, st = _glob(), {}
    state.set_llm_outage(st, "guthaben", "Anthropic-Guthaben erschöpft", _now(8).timestamp())
    with patch("watcher.main.discord_notify.post_text") as post, \
         patch("watcher.main.state.save_state"):
        _maybe_alliswell(glob, [], st, _now(9))

    post.assert_not_called()
    assert "last_alliswell" not in st    # nicht als „heute erledigt" abhaken


def test_alliswell_returns_after_recovery():
    glob, st = _glob(), {}
    state.set_llm_outage(st, "guthaben", "leer", _now(8).timestamp())
    state.clear_llm_outage(st)
    with patch("watcher.main.discord_notify.post_text") as post, \
         patch("watcher.main.state.save_state"):
        _maybe_alliswell(glob, [], st, _now(9))
    post.assert_called_once()


def test_recovery_is_announced_once_when_it_had_been_warned_about():
    glob = _glob()
    st = {"llm_recovered": {"kind": "guthaben", "reason": "Anthropic-Guthaben erschöpft",
                            "since": _now(8).timestamp() - 3600, "at": _now(9).timestamp()}}
    with patch("watcher.main.discord_notify.post_text") as post, \
         patch("watcher.main.state.save_state"):
        _maybe_llm_outage_warning(glob, st, _now(9))
        _maybe_llm_outage_warning(glob, st, _now(10))   # kein zweites Mal

    post.assert_called_once()
    assert "✅" in post.call_args[0][1]
    assert "llm_recovered" not in st
