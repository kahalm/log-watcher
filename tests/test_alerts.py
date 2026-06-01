from datetime import datetime, timezone

from watcher.config import Config
from watcher import alerts, es_client


class _S:
    def __init__(self, kind, detail, sev="medium"):
        self.kind = kind
        self.detail = detail
        self.severity_hint = sev


def test_alert_index_name():
    now = datetime(2026, 6, 1, 18, 0, tzinfo=timezone.utc)
    assert alerts.alert_index_name("log-watcher-alerts", now) == "log-watcher-alerts-2026.06"


def test_build_alert_doc_shapes_messages_as_array():
    cfg = Config()
    assessment = {"severity": "high", "summary": "x", "suspected_cause": "y",
                  "recommended_action": "z", "llm_used": True}
    signals = [_S("error_spike", "30 Fehler", "medium")]
    # Message-Keys mit Punkten/Sonderzeichen dürfen NICHT zu Feldnamen werden:
    current = {"total": 800, "levels": {"Error": 30},
               "error_messages": {"DB timeout after 30s": 25, "a.b.c weird key": 3}}
    baseline = {"total": 700, "levels": {"Error": 2}}

    doc = alerts.build_alert_doc(assessment, signals, current, baseline, cfg,
                                 "2026-06-01T18:00:00.000Z", "sig1", emailed=True)

    assert doc["@timestamp"] == "2026-06-01T18:00:00.000Z"
    assert doc["severity"] == "high"
    assert doc["emailed"] is True
    assert doc["signature"] == "sig1"
    assert isinstance(doc["window"]["top_error_messages"], list)
    assert {"message": "DB timeout after 30s", "count": 25} in doc["window"]["top_error_messages"]
    # Levels bleiben Objekt (kontrollierte Keys)
    assert doc["window"]["levels"]["Error"] == 30
    assert doc["baseline"]["total"] == 700
    assert doc["signals"][0]["kind"] == "error_spike"


def test_index_alert_posts_to_doc_endpoint(monkeypatch):
    captured = {}

    class FakeResp:
        def raise_for_status(self):
            pass

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return FakeResp()

    monkeypatch.setattr(es_client.requests, "post", fake_post)
    c = es_client.ESClient(Config())
    c.index_alert({"a": 1}, "log-watcher-alerts-2026.06")
    assert captured["url"].endswith("/log-watcher-alerts-2026.06/_doc")
    assert captured["json"] == {"a": 1}


def test_ensure_alert_template_puts_template(monkeypatch):
    captured = {}

    class FakeResp:
        def raise_for_status(self):
            pass

    def fake_put(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return FakeResp()

    monkeypatch.setattr(es_client.requests, "put", fake_put)
    c = es_client.ESClient(Config())
    c.ensure_alert_template("log-watcher-alerts")
    assert captured["url"].endswith("/_index_template/log-watcher-alerts-template")
    assert captured["json"]["template"]["settings"]["number_of_replicas"] == 0
    assert captured["json"]["index_patterns"] == ["log-watcher-alerts-*"]
