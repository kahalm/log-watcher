"""Fehler/Warnungen ohne Message-Templates dürfen nicht stumm bleiben (Fund S5-006).

Ist message_field falsch (z.B. der alte Default messageTemplate.keyword auf ECS-Logs), antwortet
ES mit 200 und leeren Buckets: error_messages bleibt leer, new_errors feuert nie, die Top-Fehler
in Alert/Digest fehlen — und bisher warnte niemand (nur mit gesetztem warn_spike_ignore).
"""
from datetime import datetime, timezone

import pytest

from watcher import rules
from watcher.config import Config
from watcher.main import run_cycle, startup_probe


@pytest.fixture(autouse=True)
def _reset_warned():
    rules._templates_missing_warned.clear()
    yield
    rules._templates_missing_warned.clear()


def _now():
    return datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)


def _cfg(name="rookhub-prod", tmp_path=None):
    cfg = Config()
    cfg.name = name
    cfg.message_field = "messageTemplate.keyword"
    if tmp_path is not None:
        cfg.state_file = str(tmp_path / "state.json")
    cfg.dry_run = True
    cfg.anthropic_api_key = None
    cfg.index_alerts = False
    cfg.index_silent_window_hours = 0
    cfg.heartbeat_max_staleness_minutes = 0
    cfg.security_check = False
    cfg.linux_check = False
    return cfg


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records
            if r.levelname == "WARNING" and "keine Message-Templates" in r.getMessage()]


class _FakeES:
    def __init__(self, window):
        self.window = window

    def aggregate_window(self, a, b):
        return dict(self.window)


_BLIND = {"total": 16211, "levels": {"Information": 15951, "Warning": 260}, "error_messages": {}, "per_index": {}}
_OK = {"total": 100, "levels": {"Warning": 3}, "error_messages": {"Timeout {Url}": 3}, "per_index": {}}


def test_warns_once_per_target_when_levels_count_but_templates_are_empty(caplog):
    cfg = _cfg()
    with caplog.at_level("WARNING", logger="log-watcher"):
        assert rules.warn_if_templates_missing(_BLIND, cfg) is True
        assert rules.warn_if_templates_missing(_BLIND, cfg) is False   # nicht je Zyklus
    msgs = _warnings(caplog)
    assert len(msgs) == 1
    assert "260" in msgs[0] and "rookhub-prod" in msgs[0] and "messageTemplate.keyword" in msgs[0]


def test_no_warning_without_errors_or_warnings(caplog):
    quiet = {"total": 500, "levels": {"Information": 500}, "error_messages": {}}
    with caplog.at_level("WARNING", logger="log-watcher"):
        assert rules.warn_if_templates_missing(quiet, _cfg()) is False
    assert _warnings(caplog) == []


def test_no_warning_when_templates_arrive(caplog):
    with caplog.at_level("WARNING", logger="log-watcher"):
        assert rules.warn_if_templates_missing(_OK, _cfg()) is False
    assert _warnings(caplog) == []


def test_warning_rearms_after_templates_worked_again(caplog):
    cfg = _cfg()
    with caplog.at_level("WARNING", logger="log-watcher"):
        rules.warn_if_templates_missing(_BLIND, cfg)
        rules.warn_if_templates_missing(_OK, cfg)
        rules.warn_if_templates_missing(_BLIND, cfg)
    assert len(_warnings(caplog)) == 2


def test_each_target_warns_on_its_own(caplog):
    with caplog.at_level("WARNING", logger="log-watcher"):
        rules.warn_if_templates_missing(_BLIND, _cfg("rookhub-prod"))
        rules.warn_if_templates_missing(_BLIND, _cfg("rookhub-dev"))
    assert len(_warnings(caplog)) == 2


def test_warning_is_independent_of_warn_spike_ignore(caplog):
    cfg = _cfg()
    cfg.warn_spike_ignore = []
    with caplog.at_level("WARNING", logger="log-watcher"):
        rules.warn_if_templates_missing(_BLIND, cfg)
    assert len(_warnings(caplog)) == 1


def test_startup_probe_warns_about_missing_templates(caplog):
    with caplog.at_level("WARNING", logger="log-watcher"):
        startup_probe(_cfg(), _FakeES(_BLIND), _now())
    msgs = _warnings(caplog)
    assert len(msgs) == 1 and msgs[0].startswith("Startup-Probe")


def test_run_cycle_warns_about_missing_templates(caplog, tmp_path):
    with caplog.at_level("WARNING", logger="log-watcher"):
        run_cycle(_cfg(tmp_path=tmp_path), _FakeES(_BLIND), _now())
    assert len(_warnings(caplog)) == 1


def test_defaults_follow_the_ecs_schema(monkeypatch):
    monkeypatch.delenv("ES_LEVEL_FIELD", raising=False)
    monkeypatch.delenv("ES_MESSAGE_FIELD", raising=False)
    cfg = Config()
    assert cfg.level_field == "log.level"
    assert cfg.message_field == "labels.MessageTemplate"
