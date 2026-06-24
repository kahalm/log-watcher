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
