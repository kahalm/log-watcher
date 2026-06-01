from datetime import datetime, timezone

from watcher.config import Config
from watcher import digest


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


class _FakeES:
    def aggregate_window(self, a, b):
        return {"total": 1000, "levels": {"Information": 900, "Error": 80, "Warning": 20},
                "error_messages": {"boom": 50}, "per_index": {}}

    def count(self, index, query):
        return 3


def test_target_summary():
    s = digest.target_summary(Config(), _FakeES(), 86400,
                              datetime(2026, 6, 1, tzinfo=timezone.utc), _iso)
    assert s["total"] == 1000 and s["errors"] == 80 and s["warnings"] == 20 and s["alerts"] == 3
    assert s["top_errors"][0] == ("boom", 50)


def test_build_quiet():
    summaries = [{"name": "a", "total": 100, "errors": 0, "warnings": 0, "alerts": 0, "top_errors": []}]
    subject, text, html = digest.build(summaries, period_days=1)
    assert "alles ruhig" in subject and "24h" in subject
    assert "a" in text


def test_build_with_alerts():
    summaries = [{"name": "a", "total": 100, "errors": 5, "warnings": 1, "alerts": 2,
                  "top_errors": [("x", 5)]}]
    subject, text, html = digest.build(summaries, period_days=7)
    assert "2 Alert" in subject and "7d" in subject
    assert "<table" in html
