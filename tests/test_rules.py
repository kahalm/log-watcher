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


def test_ingestion_stopped():
    c = _cfg()
    current = {"total": 0, "levels": {}, "error_messages": {}}
    baseline = {"total": 500, "levels": {"Information": 500}, "error_messages": {}}
    kinds = [s.kind for s in rules.evaluate(current, baseline, c)]
    assert "ingestion_stopped" in kinds


def test_overall_severity():
    sigs = rules.evaluate(
        {"total": 10, "levels": {"Fatal": 1}, "error_messages": {}},
        {"total": 10, "levels": {"Fatal": 0}, "error_messages": {}},
        _cfg(),
    )
    assert rules.overall_severity(sigs) == "high"
