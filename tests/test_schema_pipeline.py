"""Tests fuer die zentrale Ingest-Pipeline logs-schema-normalize.

Statische Checks laufen immer (validieren das JSON + den LogTags-Falt-Processor).
Der _simulate-Teil laeuft nur, wenn ein Elasticsearch erreichbar ist
(ES_TEST_URL, Default http://10.24.13.6:9200) — sonst wird er uebersprungen.
"""
import json
import os
from pathlib import Path

import pytest

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

PIPELINE_PATH = (
    Path(__file__).resolve().parent.parent
    / "schema"
    / "logs-schema-normalize.pipeline.json"
)


def _load_pipeline():
    return json.loads(PIPELINE_PATH.read_text(encoding="utf-8"))


def test_pipeline_json_is_valid():
    pipe = _load_pipeline()
    assert isinstance(pipe.get("processors"), list)
    assert pipe["processors"], "Pipeline hat keine Processors"


def test_logtags_fold_processor_present():
    """Ein Painless-Script-Processor faltet labels/metadata.LogTags in tags."""
    pipe = _load_pipeline()
    scripts = [p["script"] for p in pipe["processors"] if "script" in p]
    folder = [
        s
        for s in scripts
        if "LogTags" in s.get("source", "") and s.get("lang") == "painless"
    ]
    assert folder, "Kein Painless-Script-Processor faltet LogTags in tags"
    src = folder[0]["source"]
    # Liest aus beiden moeglichen Quellen und entfernt die Hilfs-Property.
    assert "ctx.labels" in src and "ctx.metadata" in src
    assert "remove('LogTags')" in src
    # Muss vor den heuristischen tags-append-Bloecken stehen (Reihenfolge egal fuer
    # append, aber so bleibt der Datenfluss nachvollziehbar).
    idx_script = next(
        i for i, p in enumerate(pipe["processors"]) if "script" in p
    )
    idx_first_append = next(
        i
        for i, p in enumerate(pipe["processors"])
        if "append" in p and p["append"].get("field") == "tags"
    )
    assert idx_script < idx_first_append


def _tag_condition(tag):
    pipe = _load_pipeline()
    conds = [
        p["append"].get("if", "")
        for p in pipe["processors"]
        if "append" in p and p["append"].get("field") == "tags" and p["append"].get("value") == [tag]
    ]
    assert len(conds) == 1, f"genau ein append-Prozessor fuer Tag {tag!r} erwartet"
    return conds[0]


def test_heartbeat_tag_only_from_structured_fields():
    """Fund S5-008: das Tag heartbeat blendet Zeilen in der Discover-Standardsicht aus. Per
    Freitext ('Heartbeat:' im message) traf es auch Request-Logs mit dem Text im Pfad."""
    cond = _tag_condition("heartbeat")
    assert "ctx.message" not in cond
    assert "ctx.labels?.HeartbeatService != null" in cond
    assert "endsWith('.HeartbeatService')" in cond
    # Alt-Bot-Heartbeat (ClientLog) nur ueber das strukturierte Kind, nicht per Teilstring.
    assert "ctx.labels?.ClientLogKind == 'heartbeat_bot'" in cond


# ---------------------------------------------------------------------------
# Live-_simulate (nur wenn ES erreichbar)
# ---------------------------------------------------------------------------

ES_URL = os.getenv("ES_TEST_URL", "http://10.24.13.6:9200")


def _es_reachable():
    if requests is None:
        return False
    try:
        return requests.get(ES_URL, timeout=2).ok
    except Exception:
        return False


@pytest.mark.skipif(
    not _es_reachable(), reason=f"Elasticsearch nicht erreichbar ({ES_URL})"
)
def test_simulate_logtags_folding_live():
    pipe = _load_pipeline()
    body = {
        "pipeline": pipe,
        "docs": [
            {"_source": {"message": "x", "labels": {"LogTags": "import,chessable"}}},
            {"_source": {"message": "y", "metadata": {"LogTags": "crawl"}}},
            {"_source": {"message": "z", "tags": ["daily"]}},
        ],
    }
    resp = requests.post(
        f"{ES_URL}/_ingest/pipeline/_simulate",
        headers={"Content-Type": "application/json"},
        data=json.dumps(body),
        timeout=10,
    )
    resp.raise_for_status()
    docs = [d["doc"]["_source"] for d in resp.json()["docs"]]

    # Doc 1: labels.LogTags -> tags, Property entfernt
    assert set(docs[0]["tags"]) == {"import", "chessable"}
    assert "LogTags" not in docs[0].get("labels", {})
    # Doc 2: metadata.LogTags -> tags
    assert docs[1]["tags"] == ["crawl"]
    assert "LogTags" not in docs[1].get("metadata", {})
    # Doc 3: nativer Python-tags-Array bleibt erhalten
    assert "daily" in docs[2]["tags"]


@pytest.mark.skipif(
    not _es_reachable(), reason=f"Elasticsearch nicht erreichbar ({ES_URL})"
)
def test_simulate_heartbeat_tag_live():
    pipe = _load_pipeline()
    docs_in = [
        # 0: echter Heartbeat (Property + Logger)
        {"message": "Heartbeat: rookhub-api healthy db=True uptime=60s",
         "labels": {"HeartbeatService": "rookhub-api"},
         "log": {"logger": "RookHub.Api.Services.HeartbeatService"}},
        # 1: Request-Log mit dem Text im Pfad (Scanner) -> bleibt sichtbar
        {"message": "HTTP GET /Heartbeat: x responded 404", "url": {"path": "/Heartbeat: x"},
         "http": {"response": {"status_code": 404}}},
        # 2: Alt-Bot-Heartbeat ueber ClientLog
        {"message": "ClientLog heartbeat_bot: alive", "labels": {"ClientLogKind": "heartbeat_bot"}},
        # 3: nur Logger (Property woanders abgelegt)
        {"message": "Heartbeat: rookhub-crawler healthy",
         "log": {"logger": "ChessResultsCrawler.Services.HeartbeatService"}},
        # 4: anderer ClientLog mit heartbeat_bot im Detail -> kein Tag
        {"message": "ClientLog engine_x: heartbeat_bot", "labels": {"ClientLogKind": "engine_x"}},
    ]
    resp = requests.post(
        f"{ES_URL}/_ingest/pipeline/_simulate",
        headers={"Content-Type": "application/json"},
        data=json.dumps({"pipeline": pipe, "docs": [{"_source": d} for d in docs_in]}),
        timeout=10,
    )
    resp.raise_for_status()
    docs = [d["doc"]["_source"] for d in resp.json()["docs"]]
    tagged = ["heartbeat" in (d.get("tags") or []) for d in docs]
    assert tagged == [True, False, True, True, False]
    assert all("schema_error" not in d.get("labels", {}) for d in docs)
