from watcher.config import Config
from watcher import linux
from watcher.es_client import ESClient


def _cfg(**over):
    # Defaults: ssh=20, oom=1, disk=1, unit=10, silent_min_baseline=10
    cfg = Config()
    cfg.linux_indices = ["filebeat-*"]
    for k, v in over.items():
        setattr(cfg, k, v)
    return cfg


def _host(total=1000, ssh_fail=0, oom=0, disk=0, unit_fail=0):
    return {"total": total, "ssh_fail": ssh_fail, "oom": oom, "disk": disk, "unit_fail": unit_fail}


# ── evaluate_linux: Schwellen + Falsch-Positiv-Schutz ──

def test_quiet_hosts_no_signal():
    lin = {"hosts": {"vm1": _host(ssh_fail=3, unit_fail=2), "pve": _host()},
           "baseline_hosts": {"vm1": 900, "pve": 800}}
    assert linux.evaluate_linux(lin, _cfg()) == []


def test_ssh_bruteforce_fires_and_is_forced():
    lin = {"hosts": {"vm1": _host(ssh_fail=57)}, "baseline_hosts": {}}
    sigs = linux.evaluate_linux(lin, _cfg())
    assert [s.kind for s in sigs] == ["linux_ssh_bruteforce"]
    assert sigs[0].severity_hint == "high"
    assert "vm1" in sigs[0].detail and "57" in sigs[0].detail
    assert "linux_ssh_bruteforce" in linux.FORCED_KINDS


def test_ssh_below_threshold_quiet():
    lin = {"hosts": {"vm1": _host(ssh_fail=19)}, "baseline_hosts": {}}
    assert linux.evaluate_linux(lin, _cfg()) == []


def test_oom_and_disk_fire_at_one():
    lin = {"hosts": {"pve": _host(oom=1, disk=2)}, "baseline_hosts": {}}
    kinds = [s.kind for s in linux.evaluate_linux(lin, _cfg())]
    assert kinds == ["linux_oom", "linux_disk_errors"]


def test_unit_failures_threshold():
    below = {"hosts": {"vm1": _host(unit_fail=9)}, "baseline_hosts": {}}
    at = {"hosts": {"vm1": _host(unit_fail=10)}, "baseline_hosts": {}}
    assert linux.evaluate_linux(below, _cfg()) == []
    sigs = linux.evaluate_linux(at, _cfg())
    assert [s.kind for s in sigs] == ["linux_unit_failures"]
    assert sigs[0].severity_hint == "medium"


def test_host_silent_fires_only_with_baseline():
    # vm1: Vorfenster aktiv, jetzt weg -> Signal. vm2: war schon leise -> kein Signal.
    lin = {"hosts": {"pve": _host()},
           "baseline_hosts": {"vm1": 500, "vm2": 3, "pve": 450}}
    sigs = linux.evaluate_linux(lin, _cfg())
    assert [s.kind for s in sigs] == ["linux_host_silent"]
    assert "vm1" in sigs[0].detail


def test_host_silent_check_disableable():
    lin = {"hosts": {}, "baseline_hosts": {"vm1": 500}}
    assert linux.evaluate_linux(lin, _cfg(linux_host_silent_check=False)) == []


def test_linux_check_disableable():
    lin = {"hosts": {"vm1": _host(ssh_fail=999, oom=5)}, "baseline_hosts": {}}
    assert linux.evaluate_linux(lin, _cfg(linux_check=False)) == []


def test_multiple_hosts_multiple_signals_sorted():
    lin = {"hosts": {"vm2": _host(oom=1), "vm1": _host(ssh_fail=50)}, "baseline_hosts": {}}
    kinds = [s.kind for s in linux.evaluate_linux(lin, _cfg())]
    # Hosts werden sortiert abgearbeitet -> deterministische Reihenfolge
    assert kinds == ["linux_ssh_bruteforce", "linux_oom"]


# ── ESClient._parse_linux: Aggregat-Antwort -> Schema ──

def test_parse_linux():
    resp = {"aggregations": {"by_host": {"buckets": [
        {"key": "vm1", "doc_count": 1200,
         "ssh_fail": {"doc_count": 30}, "oom": {"doc_count": 1},
         "disk": {"doc_count": 0}, "unit_fail": {"doc_count": 4}},
    ]}}}
    base = {"aggregations": {"by_host": {"buckets": [
        {"key": "vm1", "doc_count": 1100}, {"key": "vm2", "doc_count": 90},
    ]}}}
    out = ESClient._parse_linux(resp, base)
    assert out["hosts"]["vm1"] == {"total": 1200, "ssh_fail": 30, "oom": 1, "disk": 0, "unit_fail": 4}
    assert out["baseline_hosts"] == {"vm1": 1100, "vm2": 90}


def test_parse_linux_empty():
    assert ESClient._parse_linux({}, {}) == {"hosts": {}, "baseline_hosts": {}}
