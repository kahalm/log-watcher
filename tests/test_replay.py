from datetime import datetime, timezone

from watcher.config import Config
from watcher import main as m


class _FakeES:
    def __init__(self):
        self.calls = 0

    def aggregate_window(self, a, b):
        self.calls += 1
        return {"total": 100, "levels": {"Error": 10}, "error_messages": {"boom": 10}, "per_index": {}}

    def per_index_counts(self, a, b):
        return {}   # Index-Stille-Prüfung (eigenes Fenster) — hier neutral

    def security_window(self, a, b):
        return {"total_requests": 100, "suspicious": {"count": 0, "paths": {}, "ips": {}}, "by_ip": {}}


def test_replay_steps_full_windows():
    cfg = Config()  # window_hours=6, baseline previous -> 2 Aggregate je Fenster
    es = _FakeES()
    start = datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 6, 1, 18, 0, tzinfo=timezone.utc)
    rc = m.replay(cfg, es, start, end)
    assert rc == 0
    # Cursor läuft start+6h .. end (6,12,18) = 3 Fenster * (current+baseline) = 6 Aggregat-Calls
    assert es.calls == 6
