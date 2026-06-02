from watcher import main as m
from watcher import __version__


class _C:
    def __init__(self, name):
        self.name = name


def test_build_time_unknown(monkeypatch):
    monkeypatch.delenv("LOGWATCHER_BUILD_TIME", raising=False)
    assert m._build_time_str() == "unbekannt"
    monkeypatch.setenv("LOGWATCHER_BUILD_TIME", "unknown")
    assert m._build_time_str() == "unbekannt"


def test_build_time_formats_iso(monkeypatch):
    monkeypatch.setenv("LOGWATCHER_BUILD_TIME", "2026-06-02T08:30:00Z")
    s = m._build_time_str()
    assert "08:30" in s and "02.06.2026" in s


def test_startup_message(monkeypatch):
    monkeypatch.setenv("LOGWATCHER_BUILD_TIME", "2026-06-02T08:30:00Z")
    msg = m._startup_message([_C("rookhub-prod"), _C("rookhub-dev")])
    assert "log-watcher online" in msg
    assert __version__ in msg
    assert "08:30" in msg and "02.06.2026" in msg
    assert "rookhub-prod" in msg and "rookhub-dev" in msg
