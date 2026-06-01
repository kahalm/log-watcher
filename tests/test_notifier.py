from watcher.config import Config
from watcher import notifier


class _S:
    def __init__(self, kind, detail, sev="medium"):
        self.kind = kind
        self.detail = detail
        self.severity_hint = sev


def _data():
    assessment = {
        "anomalous": True, "severity": "high",
        "summary": "DB-Timeouts häufen sich.",
        "suspected_cause": "DB überlastet", "recommended_action": "Connections prüfen",
        "llm_used": True,
    }
    signals = [_S("error_spike", "30 Fehler", "medium"), _S("warn_spike", "60 Warnungen", "low")]
    current = {"total": 800, "levels": {"Error": 30, "Warning": 60}, "error_messages": {"DB timeout": 25}}
    baseline = {"total": 750, "levels": {"Error": 2}, "error_messages": {}}
    return assessment, signals, current, baseline, Config()


def test_html_contains_core_fields():
    a, s, cur, base, cfg = _data()
    html = notifier.build_email_html(a, s, cur, base, cfg)
    assert "DB-Timeouts" in html
    assert "high" in html.lower()
    assert "error_spike" in html and "warn_spike" in html
    assert "DB timeout" in html
    assert "<html" in html.lower()


def test_html_escapes_dynamic_content():
    a, s, cur, base, cfg = _data()
    cur["error_messages"] = {"<script>alert('x')</script>": 3}
    html = notifier.build_email_html(a, s, cur, base, cfg)
    assert "<script>alert" not in html       # roher Tag darf nicht durchrutschen
    assert "&lt;script&gt;" in html          # escaped


def test_plaintext_still_built():
    a, s, cur, base, cfg = _data()
    txt = notifier.build_email_body(a, s, cur, base, cfg)
    assert "DB-Timeouts" in txt
    assert "error_spike" in txt
