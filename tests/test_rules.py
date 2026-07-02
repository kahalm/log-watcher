from watcher.config import Config
from watcher import rules


def _cfg():
    # Defaults: error_levels=[Error,Fatal], min_errors=5, spike=3.0, new_sigs=on, ingestion_check=on
    return Config()


def test_no_signal_when_quiet():
    c = _cfg()
    current = {"total": 100, "levels": {"Information": 100}, "error_messages": {}}
    baseline = {"total": 100, "levels": {"Information": 100}, "error_messages": {}}
    assert rules.evaluate(current, baseline, c) == []


def test_error_spike():
    c = _cfg()
    current = {"total": 100, "levels": {"Error": 30}, "error_messages": {"boom": 30}}
    baseline = {"total": 100, "levels": {"Error": 2}, "error_messages": {"boom": 2}}
    kinds = [s.kind for s in rules.evaluate(current, baseline, c)]
    assert "error_spike" in kinds


def test_no_spike_below_min_errors():
    c = _cfg()
    current = {"total": 100, "levels": {"Error": 3}, "error_messages": {"boom": 3}}
    baseline = {"total": 100, "levels": {"Error": 0}, "error_messages": {}}
    # 3 < MIN_ERRORS(5) -> kein Spike; aber "boom" ist neu -> new_errors
    kinds = [s.kind for s in rules.evaluate(current, baseline, c)]
    assert "error_spike" not in kinds
    assert "new_errors" in kinds


def test_fatal_always():
    c = _cfg()
    current = {"total": 10, "levels": {"Fatal": 1}, "error_messages": {"x": 1}}
    baseline = {"total": 10, "levels": {"Fatal": 1}, "error_messages": {"x": 1}}
    kinds = [s.kind for s in rules.evaluate(current, baseline, c)]
    assert "fatal" in kinds


def test_new_signatures():
    c = _cfg()
    current = {"total": 50, "levels": {"Error": 3}, "error_messages": {"new-boom": 3}}
    baseline = {"total": 50, "levels": {"Error": 3}, "error_messages": {"old": 3}}
    kinds = [s.kind for s in rules.evaluate(current, baseline, c)]
    assert "new_errors" in kinds


def test_warn_spike():
    c = _cfg()  # min_warnings=20, warn_spike_factor=3.0
    current = {"total": 500, "levels": {"Warning": 60}, "error_messages": {}}
    baseline = {"total": 500, "levels": {"Warning": 5}, "error_messages": {}}
    kinds = [s.kind for s in rules.evaluate(current, baseline, c)]
    assert "warn_spike" in kinds
    assert "error_spike" not in kinds  # keine Fehler -> kein error_spike


def test_warn_spike_ignore_suppresses_softfail_noise():
    import os
    os.environ["WARN_SPIKE_IGNORE"] = "curl exited with code"
    try:
        c = Config()  # min_warnings=20, warn_spike_factor=3.0
        # 44 curl-softFail-Warnungen + 3 echte -> ohne Filter würde warn_spike feuern;
        # nach Abzug der 44 ignorierten bleiben 3 < MIN_WARNINGS(20) -> kein Signal.
        current = {"total": 5000, "levels": {"Warning": 47},
                   "error_messages": {"curl exited with code {Code}: {Stderr}": 44, "echtes problem": 3}}
        baseline = {"total": 5000, "levels": {"Warning": 1}, "error_messages": {}}
        assert "warn_spike" not in [s.kind for s in rules.evaluate(current, baseline, c)]
    finally:
        del os.environ["WARN_SPIKE_IGNORE"]


def test_warn_spike_still_fires_for_non_ignored_warnings():
    import os
    os.environ["WARN_SPIKE_IGNORE"] = "curl exited with code"
    try:
        c = Config()
        # 44 ignorierte + 30 echte Warnungen -> nach Abzug 30 >= MIN(20) und >> Baseline -> feuert.
        current = {"total": 5000, "levels": {"Warning": 74},
                   "error_messages": {"curl exited with code {Code}: {Stderr}": 44, "echtes problem": 30}}
        baseline = {"total": 5000, "levels": {"Warning": 2}, "error_messages": {}}
        sigs = rules.evaluate(current, baseline, c)
        warn = [s for s in sigs if s.kind == "warn_spike"]
        assert len(warn) == 1
        assert "30 Warnungen" in warn[0].detail        # ignorierte sind abgezogen
        assert "44 ignorierte" in warn[0].detail        # und transparent ausgewiesen
    finally:
        del os.environ["WARN_SPIKE_IGNORE"]


def test_warn_spike_ignore_also_skips_new_errors():
    # Ein ignoriertes Template darf KEIN Signal auslösen — auch nicht new_errors
    # (sonst wandert das Rauschen nur vom warn_spike- ins new_errors-Signal).
    import os
    os.environ["WARN_SPIKE_IGNORE"] = "curl exited with code"
    try:
        c = Config()
        current = {"total": 100, "levels": {"Warning": 5},
                   "error_messages": {"curl exited with code {Code}: {Stderr}": 5}}
        baseline = {"total": 100, "levels": {"Warning": 0}, "error_messages": {}}
        assert [s.kind for s in rules.evaluate(current, baseline, c)] == []
    finally:
        del os.environ["WARN_SPIKE_IGNORE"]


def test_no_warn_spike_below_min():
    c = _cfg()
    current = {"total": 500, "levels": {"Warning": 12}, "error_messages": {}}
    baseline = {"total": 500, "levels": {"Warning": 0}, "error_messages": {}}
    # 12 < MIN_WARNINGS(20) -> kein warn_spike
    assert [s.kind for s in rules.evaluate(current, baseline, c)] == []


def test_warn_spike_disabled():
    import os
    os.environ["ALERT_ON_WARN_SPIKE"] = "false"
    try:
        c = Config()
        current = {"total": 500, "levels": {"Warning": 99}, "error_messages": {}}
        baseline = {"total": 500, "levels": {"Warning": 1}, "error_messages": {}}
        assert [s.kind for s in rules.evaluate(current, baseline, c)] == []
    finally:
        del os.environ["ALERT_ON_WARN_SPIKE"]


def test_ingestion_stopped():
    c = _cfg()
    current = {"total": 0, "levels": {}, "error_messages": {}}
    baseline = {"total": 500, "levels": {"Information": 500}, "error_messages": {}}
    kinds = [s.kind for s in rules.evaluate(current, baseline, c)]
    assert "ingestion_stopped" in kinds


def test_index_silent_partial_outage():
    c = _cfg()
    cur_index = {"a-2026.06": 100, "b-2026.06": 0}   # b verstummt, a lebt weiter
    base_index = {"a-2026.06": 50, "b-2026.06": 50}
    sigs = rules.evaluate_index_silence(cur_index, base_index, c, 24)
    kinds = [s.kind for s in sigs]
    assert "index_silent" in kinds
    assert "24h-Fenster" in sigs[0].detail   # Fensterangabe in der Meldung


def test_index_silent_not_in_main_evaluate():
    # Per-Index-Stille läuft jetzt über ein eigenes Fenster, nicht über evaluate().
    c = _cfg()
    current = {"total": 100, "levels": {"Information": 100}, "error_messages": {},
               "per_index": {"a-2026.06": 100, "b-2026.06": 0}}
    baseline = {"total": 100, "levels": {"Information": 100}, "error_messages": {},
                "per_index": {"a-2026.06": 50, "b-2026.06": 50}}
    assert "index_silent" not in [s.kind for s in rules.evaluate(current, baseline, c)]


def test_index_silent_skips_when_whole_pipeline_quiet():
    # Alle Indizes still -> das ist „ingestion_stopped", nicht „index_silent".
    c = _cfg()
    sigs = rules.evaluate_index_silence({"a": 0, "b": 0}, {"a": 50, "b": 50}, c, 24)
    assert sigs == []


def test_index_silent_ignores_low_baseline():
    # Index unter min_errors-Baseline -> kein Fehlalarm bei normalem Leerlauf.
    c = _cfg()  # min_errors=5
    sigs = rules.evaluate_index_silence({"a": 100, "b": 0}, {"a": 50, "b": 3}, c, 24)
    assert sigs == []


def test_heartbeat_missing_when_count_zero():
    c = _cfg()
    sigs = rules.evaluate_heartbeats({"rookhub-api": 0, "rookhub-crawler": 4}, c)
    kinds = [s.kind for s in sigs]
    assert kinds == ["heartbeat_missing"]            # nur der tote Dienst feuert
    assert sigs[0].severity_hint == "high"
    assert "rookhub-api" in sigs[0].detail


def test_heartbeat_ok_when_all_present():
    c = _cfg()
    sigs = rules.evaluate_heartbeats({"rookhub-api": 1, "rookhub-crawler": 2, "schach-bot": 1}, c)
    assert sigs == []


def test_heartbeat_multiple_missing():
    c = _cfg()
    sigs = rules.evaluate_heartbeats({"rookhub-api": 0, "schach-bot": 0}, c)
    assert {s.kind for s in sigs} == {"heartbeat_missing"}
    assert len(sigs) == 2


def test_new_errors_respects_known_fingerprints():
    from watcher.fingerprint import fingerprint
    c = _cfg()
    current = {"total": 50, "levels": {"Error": 3}, "error_messages": {"boom code 7": 3}}
    baseline = {"total": 50, "levels": {"Error": 3}, "error_messages": {}}
    assert "new_errors" in [s.kind for s in rules.evaluate(current, baseline, c)]
    # Fingerprint bereits bekannt -> nicht mehr "neu"
    known = {fingerprint("boom code 7")}
    assert "new_errors" not in [s.kind for s in rules.evaluate(current, baseline, c, known_fingerprints=known)]


def test_new_errors_groups_by_fingerprint():
    c = _cfg()
    # "timeout after 30s/45s" sind dieselbe Signatur -> wenn baseline eine kennt, ist die andere NICHT neu
    current = {"total": 50, "levels": {"Error": 3}, "error_messages": {"timeout after 45s": 3}}
    baseline = {"total": 50, "levels": {"Error": 3}, "error_messages": {"timeout after 30s": 2}}
    assert "new_errors" not in [s.kind for s in rules.evaluate(current, baseline, c)]


def test_overall_severity():
    sigs = rules.evaluate(
        {"total": 10, "levels": {"Fatal": 1}, "error_messages": {}},
        {"total": 10, "levels": {"Fatal": 0}, "error_messages": {}},
        _cfg(),
    )
    assert rules.overall_severity(sigs) == "high"


# ── Data-Stream-Rollover: Backing-Indizes dürfen keinen Stille-Fehlalarm auslösen ──

def test_collapse_datastreams_sums_backing_indices():
    counts = {
        ".ds-rookhub-logs-generic-default-2026.06.11-000001": 20,
        ".ds-rookhub-logs-generic-default-2026.06.11-000002": 7000,
        "rookhub-logs-2026.06": 45000,   # klassischer Index bleibt eigenständig
    }
    out = rules._collapse_datastreams(counts)
    assert out["rookhub-logs-generic-default"] == 7020
    assert out["rookhub-logs-2026.06"] == 45000


def test_index_silent_ignores_datastream_rollover():
    # Altes Backing (-000001) verstummt nach Rollover, neues (-000002) lebt -> KEIN Alarm,
    # weil beide zum selben Stream gehören.
    c = _cfg()
    cur = {".ds-rookhub-logs-generic-default-2026.06.11-000002": 7000,
           ".ds-rookhub-logs-generic-default-2026.06.11-000001": 0}
    base = {".ds-rookhub-logs-generic-default-2026.06.11-000002": 50,
            ".ds-rookhub-logs-generic-default-2026.06.11-000001": 20}
    sigs = rules.evaluate_index_silence(cur, base, c, 24)
    assert [s for s in sigs if s.kind == "index_silent"] == []


def test_index_silent_still_fires_for_whole_datastream_outage():
    # Ein ganzer Stream verstummt, während ein anderer weiterlebt -> Alarm bleibt.
    c = _cfg()
    cur = {".ds-crawler-logs-generic-default-2026.06.11-000002": 0,
           ".ds-rookhub-logs-generic-default-2026.06.11-000002": 7000}
    base = {".ds-crawler-logs-generic-default-2026.06.11-000001": 1200,
            ".ds-rookhub-logs-generic-default-2026.06.11-000002": 5000}
    sigs = rules.evaluate_index_silence(cur, base, c, 24)
    silent = [s for s in sigs if s.kind == "index_silent"]
    assert len(silent) == 1
    assert "crawler-logs-generic-default" in silent[0].detail


def test_index_silent_classic_family_silent_fires_on_family_name():
    # Klassische datierte Indizes werden auf die Familie kollabiert; ist die ganze
    # Familie still (kein neuerer Monat aktiv), feuert der Alarm — auf FAMILIEN-Namen.
    c = _cfg()
    cur = {"rookhub-logs-2026.06": 0, "other-2026.06": 100}
    base = {"rookhub-logs-2026.06": 4561, "other-2026.06": 50}
    sigs = rules.evaluate_index_silence(cur, base, c, 24)
    silent = [s for s in sigs if s.kind == "index_silent"]
    assert len(silent) == 1
    assert "rookhub-logs" in silent[0].detail
    assert "2026.06" not in silent[0].detail   # Familie, nicht die datierte Einzel-Index


# ── Monats-Rollover: alte Monats-Index darf keinen Stille-Fehlalarm auslösen ──

def test_collapse_dated_indices_sums_monthly_family():
    counts = {
        "schach-bot-logs-2026.06": 290,
        "schach-bot-logs-2026.07": 18,
        "rookhub-logs-generic-default": 7000,   # bereits DS-kollabiert (kein Datum) -> bleibt
        "daily-index-2026.06.11": 3,            # Tages-Suffix wird ebenso gefaltet
    }
    out = rules._collapse_dated_indices(counts)
    assert out["schach-bot-logs"] == 308
    assert out["rookhub-logs-generic-default"] == 7000
    assert out["daily-index"] == 3


def test_index_silent_ignores_monthly_rollover():
    # Realer schach-bot-Fall: Juni-Index verstummt am 1. Juli, Juli-Index lebt ->
    # KEIN Alarm, weil beide zur selben Familie gehören.
    c = _cfg()
    cur = {"schach-bot-logs-2026.06": 0, "schach-bot-logs-2026.07": 17,
           "rookhub-logs-2026.07": 7000}
    base = {"schach-bot-logs-2026.06": 9, "schach-bot-logs-2026.07": 0,
            "rookhub-logs-2026.06": 5000}
    sigs = rules.evaluate_index_silence(cur, base, c, 24)
    assert [s for s in sigs if s.kind == "index_silent"] == []


def test_index_silent_fires_for_whole_monthly_family_outage():
    # Eine ganze Monats-Familie verstummt (kein neuerer Monat), andere lebt -> Alarm.
    c = _cfg()
    cur = {"schach-bot-logs-2026.07": 0, "rookhub-logs-2026.07": 7000}
    base = {"schach-bot-logs-2026.06": 50, "rookhub-logs-2026.06": 5000}
    sigs = rules.evaluate_index_silence(cur, base, c, 24)
    silent = [s for s in sigs if s.kind == "index_silent"]
    assert len(silent) == 1
    assert "schach-bot-logs" in silent[0].detail
