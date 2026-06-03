import json

from watcher.config import Config
from watcher import discord_notify


class _S:
    def __init__(self, kind, detail, sev="medium"):
        self.kind = kind
        self.detail = detail
        self.severity_hint = sev


def test_build_alert_payload():
    a = {"severity": "high", "summary": "DB kaputt", "suspected_cause": "X",
         "recommended_action": "Y", "llm_used": True}
    signals = [_S("error_spike", "30 Fehler", "medium"), _S("warn_spike", "60", "low")]
    cur = {"total": 800, "levels": {}, "error_messages": {}}
    base = {"total": 700}
    p = discord_notify.build_alert_payload("[log-watcher][HIGH] subj", a, signals, cur, base, Config())
    e = p["embeds"][0]
    assert e["color"] == 0xDC3545
    assert "DB kaputt" in e["description"]
    names = [f["name"] for f in e["fields"]]
    assert "Signale" in names and "Vermutete Ursache" in names and "Fenster" in names
    sig_field = next(f for f in e["fields"] if f["name"] == "Signale")
    assert "error_spike" in sig_field["value"] and "warn_spike" in sig_field["value"]


def test_alert_payload_footer_identifies_es_instance():
    """Footer trägt Target-Name + ES-URL → mehrere ES-Instanzen mit gleichen Index-Namen
    (prod vs. dev) sind im Discord-Post auseinanderzuhalten."""
    import os
    os.environ["TARGET_NAME"] = "rookhub-prod"
    os.environ["ES_URL"] = "http://10.24.13.6:9200"
    try:
        cfg = Config()
    finally:
        del os.environ["TARGET_NAME"], os.environ["ES_URL"]
    a = {"severity": "medium", "summary": "x", "llm_used": False}
    p = discord_notify.build_alert_payload("[log-watcher][rookhub-prod][MEDIUM] subj",
                                           a, [_S("warn_spike", "31")], {"total": 1, "levels": {}}, {"total": 0}, cfg)
    footer = p["embeds"][0]["footer"]["text"]
    assert "rookhub-prod" in footer and "10.24.13.6:9200" in footer


def test_post_calls_webhook(monkeypatch):
    captured = {}

    class FakeResp:
        status = 204
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["data"] = req.data
        captured["method"] = req.get_method()
        return FakeResp()

    def fake_urlopen2(req, timeout=None):
        captured["url"] = req.full_url
        captured["data"] = req.data
        captured["method"] = req.get_method()
        captured["ua"] = req.get_header("User-agent")
        return FakeResp()

    monkeypatch.setattr(discord_notify.urllib.request, "urlopen", fake_urlopen2)
    discord_notify.post_text("https://discord.com/api/webhooks/xyz", "hallo")
    assert captured["url"] == "https://discord.com/api/webhooks/xyz"
    assert captured["method"] == "POST"
    assert json.loads(captured["data"]) == {"content": "hallo"}
    # Discord verlangt einen User-Agent (sonst Cloudflare 403/1010):
    assert captured["ua"] and "log-watcher" in captured["ua"]


def test_validate_accepts_discord_only():
    import os
    os.environ["DISCORD_WEBHOOK_URL"] = "https://discord.com/api/webhooks/xyz"
    try:
        cfg = Config()  # kein SMTP, aber Discord -> gültig
        assert cfg.validate() == []
    finally:
        del os.environ["DISCORD_WEBHOOK_URL"]


def test_validate_requires_a_channel():
    cfg = Config()  # weder SMTP noch Discord, nicht dry_run
    assert any("Alert-Kanal" in e for e in cfg.validate())
