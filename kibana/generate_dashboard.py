#!/usr/bin/env python3
"""Erzeugt das Kibana-Saved-Objects-NDJSON für die log-watcher Alert-Historie.

Generiert: Data Views (log-watcher-alerts-*, log-watcher-cycles-*), 5 Visualisierungen, zwei
gespeicherte Suchen und ein Dashboard. Ausgabe: kibana/log-watcher-dashboard.ndjson

Aufruf:  python kibana/generate_dashboard.py
Import in Kibana 8.17: Stack Management → Saved Objects → Import.

Der Generator hält das (verschachtelte, stringifizierte) JSON wartbar — bei Änderungen
hier editieren und neu erzeugen, nicht das NDJSON von Hand.
"""
import json
import os

DV_ID = "log-watcher-alerts"
PATTERN = "log-watcher-alerts-*"
# Zyklus-Status je Target (CYCLE_STATUS_ENABLED, S5-017)
CYCLES_DV_ID = "log-watcher-cycles"
CYCLES_PATTERN = "log-watcher-cycles-*"
_SRC_REF = "kibanaSavedObjectMeta.searchSourceJSON.index"


def _search_source(extra=None):
    src = {"query": {"query": "", "language": "kuery"}, "filter": [], "indexRefName": _SRC_REF}
    if extra:
        src.update(extra)
    return json.dumps(src)


def data_view(dv_id=DV_ID, pattern=PATTERN, name="log-watcher alerts"):
    return {
        "id": dv_id,
        "type": "index-pattern",
        "attributes": {"title": pattern, "name": name, "timeFieldName": "@timestamp"},
        "references": [],
    }


def saved_search(sid="log-watcher-search", title="log-watcher: Alerts",
                 description="Alle Alerts, neueste zuerst.",
                 columns=("severity", "summary", "signals.kind", "emailed", "llm_used"), dv_id=DV_ID):
    return {
        "id": sid,
        "type": "search",
        "attributes": {
            "title": title,
            "description": description,
            "columns": list(columns),
            "sort": [["@timestamp", "desc"]],
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source()},
        },
        "references": [{"name": _SRC_REF, "type": "index-pattern", "id": dv_id}],
    }


def _viz(vid, vis_state, dv_id=DV_ID):
    return {
        "id": vid,
        "type": "visualization",
        "attributes": {
            "title": vis_state["title"],
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source()},
        },
        "references": [{"name": _SRC_REF, "type": "index-pattern", "id": dv_id}],
    }


def _count_agg():
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}


def _terms(field, size=10):
    return {"id": "3", "enabled": True, "type": "terms", "schema": "group",
            "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                       "otherBucket": False, "missingBucket": False}}


def viz_over_time(vid="log-watcher-viz-overtime", title="Alerts über Zeit (nach Severity)",
                  split_field="severity.keyword", dv_id=DV_ID):
    return _viz(vid, {
        "title": title,
        "type": "histogram",
        "aggs": [
            _count_agg(),
            {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
             "params": {"field": "@timestamp", "interval": "auto", "min_doc_count": 1,
                        "useNormalizedEsInterval": True, "drop_partials": False, "extended_bounds": {}}},
            {"id": "3", "enabled": True, "type": "terms", "schema": "group",
             "params": {"field": split_field, "orderBy": "1", "order": "desc", "size": 5,
                        "otherBucket": False, "missingBucket": False}},
        ],
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                              "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100},
                              "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True,
                           "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                           "title": {"text": "Anzahl"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                              "data": {"label": "Anzahl", "id": "1"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "showCircles": True}],
            "addTooltip": True, "addLegend": True, "legendPosition": "right",
            "times": [], "addTimeMarker": False, "labels": {"show": False},
            "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"},
        },
    }, dv_id)


def _pie(vid, title, field, size=10, dv_id=DV_ID):
    return _viz(vid, {
        "title": title,
        "type": "pie",
        "aggs": [
            _count_agg(),
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                        "otherBucket": False, "missingBucket": False}},
        ],
        "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
                   "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}},
    }, dv_id)


def dashboard():
    panels = [
        {"version": "8.17.0", "type": "visualization", "panelIndex": "1",
         "gridData": {"x": 0, "y": 0, "w": 48, "h": 15, "i": "1"},
         "embeddableConfig": {}, "panelRefName": "panel_1"},
        {"version": "8.17.0", "type": "visualization", "panelIndex": "2",
         "gridData": {"x": 0, "y": 15, "w": 24, "h": 15, "i": "2"},
         "embeddableConfig": {}, "panelRefName": "panel_2"},
        {"version": "8.17.0", "type": "visualization", "panelIndex": "3",
         "gridData": {"x": 24, "y": 15, "w": 24, "h": 15, "i": "3"},
         "embeddableConfig": {}, "panelRefName": "panel_3"},
        {"version": "8.17.0", "type": "search", "panelIndex": "4",
         "gridData": {"x": 0, "y": 30, "w": 48, "h": 20, "i": "4"},
         "embeddableConfig": {}, "panelRefName": "panel_4"},
        # Zyklus-Status (nur befüllt mit CYCLE_STATUS_ENABLED=true)
        {"version": "8.17.0", "type": "visualization", "panelIndex": "5",
         "gridData": {"x": 0, "y": 50, "w": 24, "h": 15, "i": "5"},
         "embeddableConfig": {}, "panelRefName": "panel_5"},
        {"version": "8.17.0", "type": "visualization", "panelIndex": "6",
         "gridData": {"x": 24, "y": 50, "w": 24, "h": 15, "i": "6"},
         "embeddableConfig": {}, "panelRefName": "panel_6"},
        {"version": "8.17.0", "type": "search", "panelIndex": "7",
         "gridData": {"x": 0, "y": 65, "w": 48, "h": 20, "i": "7"},
         "embeddableConfig": {}, "panelRefName": "panel_7"},
    ]
    return {
        "id": "log-watcher-dashboard",
        "type": "dashboard",
        "attributes": {
            "title": "log-watcher — Alert-Historie",
            "description": "Alerts des log-watcher: Verlauf nach Severity, Verteilung der Signale, Alert-Tabelle; "
                           "darunter der Zyklus-Status je Target (Erfolg/Fehlschlag, Ergebnis, Dauer).",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "timeRestore": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": [
            {"name": "panel_1", "type": "visualization", "id": "log-watcher-viz-overtime"},
            {"name": "panel_2", "type": "visualization", "id": "log-watcher-viz-severity"},
            {"name": "panel_3", "type": "visualization", "id": "log-watcher-viz-signals"},
            {"name": "panel_4", "type": "search", "id": "log-watcher-search"},
            {"name": "panel_5", "type": "visualization", "id": "log-watcher-viz-cycles-overtime"},
            {"name": "panel_6", "type": "visualization", "id": "log-watcher-viz-cycles-result"},
            {"name": "panel_7", "type": "search", "id": "log-watcher-search-cycles"},
        ],
    }


def build_objects():
    return [
        data_view(),
        viz_over_time(),
        _pie("log-watcher-viz-severity", "Alerts nach Severity", "severity.keyword", size=5),
        _pie("log-watcher-viz-signals", "Häufigste Signale", "signals.kind.keyword", size=10),
        saved_search(),
        data_view(CYCLES_DV_ID, CYCLES_PATTERN, "log-watcher cycles"),
        viz_over_time("log-watcher-viz-cycles-overtime", "Zyklen über Zeit (Erfolg/Fehlschlag)",
                      "event.outcome.keyword", CYCLES_DV_ID),
        _pie("log-watcher-viz-cycles-result", "Zyklen nach Ergebnis", "log-watcher.result.keyword",
             size=10, dv_id=CYCLES_DV_ID),
        saved_search("log-watcher-search-cycles", "log-watcher: Zyklen",
                     "Zyklus-Status je Target, neueste zuerst.",
                     ("log-watcher.target", "event.outcome", "log-watcher.result", "log-watcher.signals",
                      "log-watcher.signal_kinds", "event.duration", "log-watcher.error"), CYCLES_DV_ID),
        dashboard(),
    ]


def main():
    objs = build_objects()
    out = os.path.join(os.path.dirname(__file__), "log-watcher-dashboard.ndjson")
    with open(out, "w", encoding="utf-8") as f:
        for o in objs:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
        # Export-Summary-Zeile (wie bei einem echten Kibana-Export)
        f.write(json.dumps({"exportedCount": len(objs), "missingRefCount": 0, "missingReferences": []}) + "\n")
    print(f"{len(objs)} Objekte -> {out}")


if __name__ == "__main__":
    main()
