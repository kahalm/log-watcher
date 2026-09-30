"""State/Heartbeat nicht schreibbar — laut statt lautlos (Fund S5-010).

Szenario: /data gehört root, der Container läuft (nach einer USER-Umstellung) nicht als root,
oder die Platte ist voll. save_state und write_heartbeat schluckten den OSError mit `pass`:
Cooldown-Stempel, last_alliswell und LLM-Tagesbudget gingen je Zyklus verloren — derselbe Alarm
alle 10 min, LLM_MAX_CALLS_PER_DAY griff nie —, ohne eine Logzeile oder Metrik.
"""
import errno
import logging
import os

import pytest

from watcher import health, main as m, state
from watcher.config import Config
from watcher.metrics import METRICS


@pytest.fixture(autouse=True)
def _fresh_write_state():
    """Jeder Test beginnt ohne gemerkten Ausfall (die ERROR-Zeile kommt einmal je Ausfall)."""
    failing = getattr(state, "_write_failing", set())
    failing.clear()
    yield
    failing.clear()


def _no_space(*_a, **_kw):
    raise OSError(errno.ENOSPC, "No space left on device")


def _errors(caplog):
    return [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_save_state_failure_is_logged_once_counted_and_cleaned_up(tmp_path, monkeypatch, caplog):
    path = str(tmp_path / "state.json")
    before = METRICS.state_write_errors_total
    monkeypatch.setattr(state.os, "replace", _no_space)
    with caplog.at_level(logging.INFO, logger="log-watcher"):
        assert state.save_state(path, {"a": 1}) is False
        assert state.save_state(path, {"a": 2}) is False
        assert state.save_state(path, {"a": 3}) is False

    errors = _errors(caplog)
    assert len(errors) == 1                                  # einmal, nicht je Zyklus
    assert "STATE_FILE" in errors[0].getMessage() and path in errors[0].getMessage()
    assert "Cooldown" in errors[0].getMessage()              # sagt, was verloren geht
    assert METRICS.state_write_errors_total - before == 3    # die Metrik zählt jeden Fehlschlag
    assert os.listdir(tmp_path) == []                        # keine liegengebliebene .tmp-Datei


def test_save_state_recovery_is_logged_and_rearms_the_error(tmp_path, monkeypatch, caplog):
    path = str(tmp_path / "state.json")
    real_replace = os.replace
    monkeypatch.setattr(state.os, "replace", _no_space)
    with caplog.at_level(logging.INFO, logger="log-watcher"):
        state.save_state(path, {"a": 1})
        monkeypatch.setattr(state.os, "replace", real_replace)
        assert state.save_state(path, {"a": 2}) is True
        assert any("wieder schreibbar" in r.getMessage() for r in caplog.records)
        monkeypatch.setattr(state.os, "replace", _no_space)
        state.save_state(path, {"a": 3})
    assert len(_errors(caplog)) == 2                          # neuer Ausfall -> neue ERROR-Zeile
    assert state.load_state(path) == {"a": 2}


def test_heartbeat_failure_is_logged_once_and_counted(tmp_path, monkeypatch, caplog):
    path = str(tmp_path / "heartbeat")
    before = METRICS.state_write_errors_total
    monkeypatch.setattr(state.tempfile, "mkstemp", _no_space)
    with caplog.at_level(logging.INFO, logger="log-watcher"):
        for _ in range(3):
            assert health.write_heartbeat(path, now=1000.0) is False
    errors = _errors(caplog)
    assert len(errors) == 1
    assert "HEARTBEAT_FILE" in errors[0].getMessage()
    assert METRICS.state_write_errors_total - before == 3


def test_state_write_errors_are_exported_as_metric():
    assert "log_watcher_state_write_errors_total" in METRICS.prometheus()
    assert "state_write_errors_total" in METRICS.status()


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root darf trotz 0555 schreiben")
def test_check_writable_reports_a_read_only_directory(tmp_path):
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o555)
    try:
        err = state.check_writable(str(ro / "state.json"))
    finally:
        ro.chmod(0o755)
    assert err is not None and "PermissionError" in err
    assert state.check_writable(str(tmp_path / "ok" / "state.json")) is None
    assert os.listdir(tmp_path / "ok") == []                  # die Probe räumt hinter sich auf


class _NoES:
    def __init__(self, _cfg):
        pass

    def aggregate_window(self, a, b):
        return {"total": 1, "levels": {"Information": 1}, "error_messages": {}, "per_index": {}}


def _loop_cfg(tmp_path, state_dir):
    cfg = Config()
    cfg.name = "t"
    cfg.es_url = "http://es.invalid:9200"
    cfg.es_indices = ["logs-*"]
    cfg.dry_run = True
    cfg.run_once = True
    cfg.replay_from = None
    cfg.selftest = False
    cfg.notify_on_start = False
    cfg.http_port = 0
    cfg.index_alerts = False
    cfg.state_file = str(state_dir / "state.json")
    cfg.heartbeat_file = str(tmp_path / "hb" / "heartbeat")
    return cfg


def test_main_refuses_to_start_when_the_state_dir_is_not_writable(tmp_path, monkeypatch, caplog):
    cfg = _loop_cfg(tmp_path, tmp_path / "data")
    monkeypatch.setattr(m, "load_targets", lambda: [cfg])
    monkeypatch.setattr(m, "ESClient", _NoES)
    monkeypatch.setattr(m.signal, "signal", lambda *_a: None)
    monkeypatch.setattr(m, "_run_cycles", lambda clients, now: {c.name: None for c, _ in clients})
    monkeypatch.setattr(m.state, "check_writable",
                        lambda p: "PermissionError: [Errno 13] Permission denied" if p == cfg.state_file else None)
    with caplog.at_level(logging.ERROR, logger="log-watcher"):
        assert m.main() == 1
    msg = " ".join(r.getMessage() for r in caplog.records)
    assert "STATE_FILE" in msg and cfg.state_file in msg and "Start abgebrochen" in msg


def test_main_starts_when_the_data_dir_is_writable(tmp_path, monkeypatch):
    cfg = _loop_cfg(tmp_path, tmp_path / "data")
    monkeypatch.setattr(m, "load_targets", lambda: [cfg])
    monkeypatch.setattr(m, "ESClient", _NoES)
    monkeypatch.setattr(m.signal, "signal", lambda *_a: None)
    monkeypatch.setattr(m, "_run_cycles", lambda clients, now: {c.name: None for c, _ in clients})
    assert m.main() == 0
    assert health.read_heartbeat(cfg.heartbeat_file) is not None
