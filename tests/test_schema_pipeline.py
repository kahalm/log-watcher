"""Tests fuer die zentrale Ingest-Pipeline logs-schema-normalize.

Statische Checks laufen immer (validieren das JSON + den LogTags-Falt-Processor).
Der _simulate-Teil laeuft nur, wenn ein Elasticsearch erreichbar ist
(ES_TEST_URL, KEIN Default — ohne die Variable wird er uebersprungen und es geht kein Netz raus).
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


def test_dotted_log_level_is_folded_before_information_default():
    """Fund S5-021: der ECS-Sink schreibt den Level als gepunkteten Schluessel 'log.level'. Ohne
    Einsammeln sieht der Default-Prozessor ctx.log.level leer, setzt 'Information' und jedes
    Dokument traegt zwei Level (Kibana zeigt einen 502 als Information, Level-Aggs zaehlen doppelt).
    Der Fix muss in DIESER Datei stehen - apply.sh ersetzt die Pipeline bei jedem Lauf komplett."""
    procs = _load_pipeline()["processors"]
    idx_default = next(
        i
        for i, p in enumerate(procs)
        if "set" in p and p["set"].get("field") == "log.level" and p["set"].get("value") == "Information"
    )
    folders = [
        i
        for i, p in enumerate(procs)
        if "script" in p
        and p["script"].get("lang") == "painless"
        and "ctx.remove('log.level')" in p["script"].get("source", "")
    ]
    assert folders, "Kein Script-Prozessor sammelt den gepunkteten Schluessel 'log.level' ein"
    assert folders[0] < idx_default, "Level-Fix muss VOR dem Information-Default laufen"
    src = procs[folders[0]]["script"]["source"]
    assert "ctx.containsKey('log.level')" in src
    assert "ctx.log.level = " in src
    # Wirft nie: ein skalares ctx.log wird nicht angefasst (sonst schema_error + Rest-Pipeline weg).
    assert "ctx.log instanceof Map" in src


# ---------------------------------------------------------------------------
# Live-_simulate (nur wenn ES erreichbar)
# ---------------------------------------------------------------------------

# Live-Tests NUR bei ausdruecklicher Vorgabe: ohne ES_TEST_URL wird KEIN Netz angefasst. Vorher stand hier die
# Prod-Elasticsearch als Default — jeder volle Testlauf auf dem Host fragte sie schon beim Sammeln an
# (Codereview 2026-09-29, Welle W4s-Abschluss).
ES_URL = os.getenv("ES_TEST_URL", "")


def _es_reachable():
    if requests is None or not ES_URL:
        return False
    try:
        return requests.get(ES_URL, timeout=2).ok
    except Exception:
        return False


@pytest.mark.skipif(
    not _es_reachable(), reason=f"Elasticsearch nicht erreichbar oder ES_TEST_URL nicht gesetzt ({ES_URL or '-'})"
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
    not _es_reachable(), reason=f"Elasticsearch nicht erreichbar oder ES_TEST_URL nicht gesetzt ({ES_URL or '-'})"
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


@pytest.mark.skipif(
    not _es_reachable(), reason=f"Elasticsearch nicht erreichbar oder ES_TEST_URL nicht gesetzt ({ES_URL or '-'})"
)
def test_simulate_dotted_log_level_live():
    """Die Faelle aus rookhub/TODO.md (Level-Fund) plus Reindex eines schon doppelt getaggten
    Dokuments und ein skalares 'log'-Feld."""
    pipe = _load_pipeline()
    docs_in = [
        # 0/1: ECS-Sink, gepunktet Error/Warning (log-Objekt mit logger existiert daneben)
        {"message": "a", "log.level": "Error", "log": {"logger": "RookHub.Api.X"}},
        {"message": "b", "log.level": "Warning"},
        # 2: ohne Level -> Vorgabe Information
        {"message": "c"},
        # 3: Altformat 'level' -> weiterhin uebernommen
        {"message": "d", "level": "Error"},
        # 4: Reindex eines alten Dokuments (verschachtelt Default + gepunktet echt) -> echter Wert
        {"message": "e", "log.level": "Fatal", "log": {"level": "Information", "logger": "Y"}},
        # 5: skalares log-Feld -> Level-Fix fasst nichts an, gepunkteter Schluessel bleibt (der
        #    nachfolgende Information-Default scheitert daran wie bisher -> schema_error)
        {"message": "f", "log.level": "Error", "log": "text"},
    ]
    resp = requests.post(
        f"{ES_URL}/_ingest/pipeline/_simulate",
        headers={"Content-Type": "application/json"},
        data=json.dumps({"pipeline": pipe, "docs": [{"_source": d} for d in docs_in]}),
        timeout=10,
    )
    resp.raise_for_status()
    docs = [d["doc"]["_source"] for d in resp.json()["docs"]]
    nested = [(d.get("log") or {}).get("level") if isinstance(d.get("log"), dict) else None for d in docs]
    assert nested[:5] == ["Error", "Warning", "Information", "Error", "Fatal"]
    assert all("log.level" not in d for d in docs[:5])
    assert docs[0]["log"]["logger"] == "RookHub.Api.X"
    assert docs[5]["log.level"] == "Error"
    assert all("schema_error" not in d.get("labels", {}) for d in docs[:5])
