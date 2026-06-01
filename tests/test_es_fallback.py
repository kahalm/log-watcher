from watcher.config import Config
from watcher.es_client import ESClient, ESError


def _client():
    return ESClient(Config())


def test_falls_back_to_levels_only_on_4xx_for_message_agg():
    c = _client()
    calls = []

    def fake_search(body):
        calls.append(body)
        # Erster (voller) Body hat die errors/top_messages-Aggregation -> simuliere 400.
        if "errors" in body.get("aggs", {}):
            raise ESError("illegal_argument: field not aggregatable", status=400)
        return {"hits": {"total": {"value": 42}},
                "aggregations": {"by_level": {"buckets": [{"key": "Error", "doc_count": 7}]}}}

    c._search = fake_search
    out = c.aggregate_window("a", "b")
    assert out["total"] == 42
    assert out["levels"]["Error"] == 7
    assert out["error_messages"] == {}          # message-Agg wurde ausgelassen
    assert len(calls) == 2                        # voll -> levels-only


def test_falls_back_to_total_only_when_level_field_bad():
    c = _client()

    def fake_search(body):
        if "aggs" in body:
            raise ESError("illegal_argument: level field", status=400)
        return {"hits": {"total": {"value": 5}}}

    c._search = fake_search
    out = c.aggregate_window("a", "b")
    assert out["total"] == 5
    assert out["levels"] == {}


def test_connection_error_is_not_swallowed():
    c = _client()

    def fake_search(body):
        raise ESError("ES nicht erreichbar", status=None)

    c._search = fake_search
    try:
        c.aggregate_window("a", "b")
        assert False, "ESError erwartet"
    except ESError as e:
        assert e.status is None


def test_server_error_is_not_swallowed():
    c = _client()

    def fake_search(body):
        raise ESError("ES HTTP 503", status=503)

    c._search = fake_search
    try:
        c.aggregate_window("a", "b")
        assert False, "ESError erwartet"
    except ESError as e:
        assert e.status == 503
