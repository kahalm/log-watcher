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
    current = {"total": 100, "levels": {"Information": 100}, "error_messages": {},
               "per_index": {"a-2026.06": 100, "b-2026.06": 0}}
    baseline = {"total": 100, "levels": {"Information": 100}, "error_messages": {},
                "per_index": {"a-2026.06": 50, "b-2026.06": 50}}
    kinds = [s.kind for s in rules.evaluate(current, baseline, c)]
    assert "index_silent" in kinds        # b verstummt, a lebt weiter
    assert "ingestion_stopped" not in kinds


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
