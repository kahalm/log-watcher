from watcher.config import Config
from watcher import security
from watcher.es_client import ESClient


def _cfg():
    # Defaults: min_suspicious=3, scan_min_4xx=40, scan_min_paths=15, auth_fail=25
    return Config()


# ── evaluate_security: Schwellen + Falsch-Positiv-Schutz ──

def test_quiet_traffic_no_signal():
    sec = {"total_requests": 5000, "suspicious": {"count": 0, "paths": {}, "ips": {}},
           "by_ip": {"1.2.3.4": {"total": 4000, "c4xx": 2, "auth_fail": 0, "distinct_paths": 3}}}
    assert security.evaluate_security(sec, _cfg()) == []


def test_suspicious_paths_fire():
    sec = {"total_requests": 1000,
           "suspicious": {"count": 12, "paths": {"/.env": 4, "/wp-login.php": 8},
                          "ips": {"45.9.1.2": 12}},
           "by_ip": {}}
    sigs = security.evaluate_security(sec, _cfg())
    assert [s.kind for s in sigs] == ["suspicious_requests"]
    assert sigs[0].severity_hint == "high"
    assert "45.9.1.2" in sigs[0].detail


def test_suspicious_below_threshold_quiet():
    sec = {"total_requests": 1000, "suspicious": {"count": 2, "paths": {"/.env": 2}, "ips": {"x": 2}},
           "by_ip": {}}
    assert security.evaluate_security(sec, _cfg()) == []


def test_api_scan_detected():
    sec = {"total_requests": 2000, "suspicious": {"count": 0, "paths": {}, "ips": {}},
           "by_ip": {"5.6.7.8": {"total": 200, "c4xx": 120, "auth_fail": 0, "distinct_paths": 80}}}
    sigs = security.evaluate_security(sec, _cfg())
    assert [s.kind for s in sigs] == ["api_scan"]
    assert "5.6.7.8" in sigs[0].detail


def test_legit_repeated_404_on_few_paths_not_a_scan():
    # Bot trifft wiederholt 2 Endpoints -> viele 4xx, aber wenige Pfade -> KEIN Scan.
    sec = {"total_requests": 2000, "suspicious": {"count": 0, "paths": {}, "ips": {}},
           "by_ip": {"172.26.0.1": {"total": 300, "c4xx": 290, "auth_fail": 0, "distinct_paths": 2}}}
    assert security.evaluate_security(sec, _cfg()) == []


def test_auth_bruteforce_detected():
    sec = {"total_requests": 500, "suspicious": {"count": 0, "paths": {}, "ips": {}},
           "by_ip": {"9.9.9.9": {"total": 60, "c4xx": 60, "auth_fail": 55, "distinct_paths": 1}}}
    sigs = security.evaluate_security(sec, _cfg())
    kinds = [s.kind for s in sigs]
    assert "auth_bruteforce" in kinds
    assert "9.9.9.9" in [s.detail for s in sigs if s.kind == "auth_bruteforce"][0]


def test_disabled_via_config():
    import os
    os.environ["SECURITY_CHECK"] = "false"
    try:
        c = Config()
        sec = {"total_requests": 1000, "suspicious": {"count": 99, "paths": {"/.env": 99}, "ips": {"x": 99}},
               "by_ip": {}}
        assert security.evaluate_security(sec, c) == []
    finally:
        del os.environ["SECURITY_CHECK"]


def test_security_kinds_constant():
    assert security.SECURITY_KINDS == {"suspicious_requests", "api_scan", "auth_bruteforce"}


# ── ESClient._parse_security: Aggregations-Antwort korrekt auslesen ──

def test_parse_security_response():
    resp = {
        "hits": {"total": {"value": 1234}},
        "aggregations": {
            "suspicious": {"doc_count": 7,
                           "paths": {"buckets": [{"key": "/.env", "doc_count": 5},
                                                 {"key": "/wp-login.php", "doc_count": 2}]},
                           "ips": {"buckets": [{"key": "45.9.1.2", "doc_count": 7}]}},
            "by_ip": {"buckets": [
                {"key": "45.9.1.2", "doc_count": 90,
                 "c4xx": {"doc_count": 88}, "auth_fail": {"doc_count": 0},
                 "distinct_paths": {"value": 60}},
            ]},
        },
    }
    out = ESClient._parse_security(resp)
    assert out["total_requests"] == 1234
    assert out["suspicious"]["count"] == 7
    assert out["suspicious"]["paths"]["/.env"] == 5
    assert out["by_ip"]["45.9.1.2"]["c4xx"] == 88
    assert out["by_ip"]["45.9.1.2"]["distinct_paths"] == 60


def test_parse_security_empty():
    out = ESClient._parse_security({"hits": {"total": {"value": 0}}, "aggregations": {}})
    assert out == {"total_requests": 0,
                   "suspicious": {"count": 0, "paths": {}, "ips": {}},
                   "by_ip": {}}


# ── auth_bruteforce: nur Auth-Endpunkte zählen (abgelaufene Tokens sind kein Angriff) ──

def test_expired_token_polling_is_not_bruteforce():
    # Legitimer Client pollt mit abgelaufenem Token: 360x 401 auf /api/notifications,
    # aber 0 auf /api/auth/* -> kein 🚨-Alarm.
    sec = {"total_requests": 400, "suspicious": {"count": 0, "paths": {}, "ips": {}},
           "by_ip": {"10.0.0.5": {"total": 360, "c4xx": 360, "auth_fail": 360,
                                  "auth_fail_scoped": 0, "distinct_paths": 2}}}
    assert [s.kind for s in security.evaluate_security(sec, _cfg())] == []


def test_bruteforce_on_auth_endpoints_fires():
    sec = {"total_requests": 400, "suspicious": {"count": 0, "paths": {}, "ips": {}},
           "by_ip": {"9.9.9.9": {"total": 90, "c4xx": 90, "auth_fail": 90,
                                 "auth_fail_scoped": 88, "distinct_paths": 1}}}
    sigs = security.evaluate_security(sec, _cfg())
    assert [s.kind for s in sigs] == ["auth_bruteforce"]
    assert "88" in sigs[0].detail and "/api/auth" in sigs[0].detail


def test_falls_back_to_unscoped_count_when_agg_missing():
    # Fehlt der gescopte Zähler (Feld/Aggregation nicht vorhanden), gilt das alte Verhalten —
    # der Security-Check darf nicht still verstummen.
    sec = {"total_requests": 400, "suspicious": {"count": 0, "paths": {}, "ips": {}},
           "by_ip": {"9.9.9.9": {"total": 60, "c4xx": 60, "auth_fail": 55, "distinct_paths": 1}}}
    assert [s.kind for s in security.evaluate_security(sec, _cfg())] == ["auth_bruteforce"]


def test_security_window_scopes_auth_agg_to_prefix():
    captured = {}

    def fake_search(body, index=None):
        captured["body"] = body
        return {"hits": {"total": {"value": 0}}, "aggregations": {}}

    c = ESClient(_cfg())
    c._search = fake_search
    c.security_window("a", "b")
    scoped = captured["body"]["aggs"]["by_ip"]["aggs"]["auth_fail_scoped"]["filter"]
    assert scoped["bool"]["must"][1]["prefix"]["url.path"]["value"] == "/api/auth"
    # ungescopter Zähler bleibt erhalten (Fallback/Transparenz)
    assert captured["body"]["aggs"]["by_ip"]["aggs"]["auth_fail"]["filter"] == {
        "terms": {"http.response.status_code": [401, 403]}}
