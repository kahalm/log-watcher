import json

from watcher.metrics import Metrics, METRICS
from watcher import httpserver


def test_metrics_counters_and_prometheus():
    m = Metrics()
    m.mark_cycle(1000.0)
    m.add_signals(["error_spike", "warn_spike"])
    m.inc("alerts_total")
    m.inc("llm_tokens_total", 123)
    s = m.status()
    assert s["cycles_total"] == 1
    assert s["alerts_total"] == 1
    assert s["llm_tokens_total"] == 123
    assert s["signals_total"]["error_spike"] == 1
    prom = m.prometheus()
    assert "log_watcher_cycles_total 1" in prom
    assert 'log_watcher_signals_total{kind="error_spike"} 1' in prom
    assert "log_watcher_last_cycle_timestamp_seconds 1000" in prom


def test_route_healthz(tmp_path):
    from watcher import health
    hb = str(tmp_path / "hb")
    health.write_heartbeat(hb, now=1_000_000_000.0)  # uralt -> stale
    code, _ctype, body = httpserver.route("/healthz", hb, max_stale=180)
    assert code == 503 and body == "stale"
    health.write_heartbeat(hb)  # jetzt frisch
    code, _ctype, body = httpserver.route("/healthz", hb, max_stale=180)
    assert code == 200 and body == "ok"


def test_route_status_and_metrics_and_404(tmp_path):
    hb = str(tmp_path / "hb")
    code, ctype, body = httpserver.route("/status", hb, 180)
    assert code == 200 and ctype == "application/json"
    json.loads(body)  # valides JSON
    code, ctype, body = httpserver.route("/metrics", hb, 180)
    assert code == 200 and "log_watcher_cycles_total" in body
    code, _c, _b = httpserver.route("/nope", hb, 180)
    assert code == 404
