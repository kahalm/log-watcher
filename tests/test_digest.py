import re
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


class _MappedAlertES(_FakeES):
    """Alert-Index wie ES ihn dynamisch anlegt: target = text (Standard-Analyzer) + target.keyword.

    Wertet den term-Filter der Count-Query aus wie ES: auf dem Textfeld gegen die Tokens, auf
    .keyword gegen den ganzen Wert.
    """
    def __init__(self, targets):
        self.targets = targets
        self.queries = []

    def count(self, index, query):
        self.queries.append((index, query))
        terms = [c["term"] for c in query["bool"]["must"] if "term" in c]
        assert len(terms) == 1
        (field, value), = terms[0].items()

        def hit(target):
            if field == "target.keyword":
                return target == value
            if field == "target":
                return value in re.findall(r"[a-z0-9]+", target.lower())
            return False

        return sum(1 for t in self.targets if hit(t))


def test_target_summary_counts_alerts_of_hyphenated_target():
    """Fund S5-007: 7 von 8 Prod-Targets heissen wie rookhub-prod; der term auf dem Textfeld
    zaehlte dort immer 0 und der Digest meldete "alles ruhig"."""
    cfg = Config()
    cfg.name = "rookhub-prod"
    es = _MappedAlertES(["rookhub-prod", "rookhub-prod", "rookhub-prod", "rookhub-dev", "servers"])
    s = digest.target_summary(cfg, es, 86400, datetime(2026, 9, 29, tzinfo=timezone.utc), _iso)
    assert s["alerts"] == 3
    index, query = es.queries[0]
    assert index == f"{cfg.alert_index_prefix}-*"
    assert {"term": {"target.keyword": "rookhub-prod"}} in query["bool"]["must"]
    assert {"range": {"@timestamp": {"gte": "2026-09-28T00:00:00.000Z",
                                     "lt": "2026-09-29T00:00:00.000Z"}}} in query["bool"]["must"]


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


def test_digest_scrubs_pii_in_top_errors():
    """Der Digest geht per Mail UND Discord raus — die Fehlermeldungen kommen roh aus ES.
    Ohne Redaktion landeten Client-IPs, Mailadressen und Tokens im Klartext beim Empfänger,
    obwohl SCRUB_PII aktiv ist (der Zyklus-Pfad schrubbt seine Meldungen längst)."""
    msgs = {"Login failed for max@example.com from 45.9.1.2": 7,
            "Bearer eyJabcdefghijklmnop abgelehnt": 3}

    redigiert = digest._scrubbed_errors(msgs, True)

    joined = " ".join(m for m, _ in redigiert)
    assert "max@example.com" not in joined
    assert "45.9.1.2" not in joined
    assert "eyJabcdefghijklmnop" not in joined
    assert [c for _, c in redigiert] == [7, 3]          # Zähler bleiben erhalten
    # Ohne Scrubbing bleibt alles wie gehabt (Opt-out muss weiter funktionieren).
    assert digest._scrubbed_errors(msgs, False) == list(msgs.items())
