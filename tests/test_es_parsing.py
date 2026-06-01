from watcher.es_client import ESClient


def test_parse_aggregates():
    resp = {
        "hits": {"total": {"value": 1234}},
        "aggregations": {
            "by_level": {"buckets": [
                {"key": "Information", "doc_count": 1200},
                {"key": "Error", "doc_count": 34},
            ]},
            "errors": {
                "doc_count": 34,
                "top_messages": {"buckets": [
                    {"key": "DB timeout", "doc_count": 20},
                    {"key": "null ref", "doc_count": 14},
                ]},
            },
            "by_index": {"buckets": [
                {"key": "rookhub-logs-2026.06", "doc_count": 1000},
                {"key": "crawler-logs-2026.06", "doc_count": 234},
            ]},
        },
    }
    out = ESClient._parse(resp)
    assert out["total"] == 1234
    assert out["levels"]["Error"] == 34
    assert out["levels"]["Information"] == 1200
    assert out["error_messages"]["DB timeout"] == 20
    assert out["per_index"]["rookhub-logs-2026.06"] == 1000


def test_parse_empty():
    out = ESClient._parse({})
    assert out == {"total": 0, "levels": {}, "error_messages": {}, "per_index": {}}
