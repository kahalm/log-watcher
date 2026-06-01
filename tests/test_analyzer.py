from watcher.config import Config
from watcher import analyzer


class _S:
    def __init__(self, kind, detail, sev="medium"):
        self.kind = kind
        self.detail = detail
        self.severity_hint = sev


def _data():
    return ({"total": 100, "levels": {"Error": 30}, "error_messages": {"boom": 30}},
            {"total": 100, "levels": {"Error": 2}, "error_messages": {}},
            [_S("error_spike", "30 Fehler")])


def test_rule_based_when_llm_disabled():
    cur, base, sig = _data()
    a = analyzer.assess(Config(), cur, base, sig, use_llm=False)
    assert a["anomalous"] is True
    assert a["llm_used"] is False
    assert a["llm_tokens"] == 0
    assert a["severity"] == "medium"  # error_spike-Hint


def test_no_key_defaults_to_rule_based():
    cur, base, sig = _data()
    a = analyzer.assess(Config(), cur, base, sig)  # kein ANTHROPIC_API_KEY -> use_llm=False
    assert a["llm_used"] is False
