"""Elasticsearch-Aggregat-Abfragen (ausschließlich lesend, size=0).

Robust gegen Fehlkonfiguration der Feldnamen: schlägt die volle Aggregation fehl
(z.B. message_field nicht aggregierbar), wird stufenweise reduziert, statt den
ganzen Zyklus zu verlieren.
"""
from __future__ import annotations

import base64
import logging

import requests

log = logging.getLogger("log-watcher")


class ESError(Exception):
    def __init__(self, message: str, status: "int | None" = None):
        super().__init__(message)
        self.status = status  # HTTP-Status (4xx/5xx) oder None bei Verbindungsfehler


class ESClient:
    def __init__(self, cfg):
        self.cfg = cfg

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.cfg.es_api_key:
            h["Authorization"] = f"ApiKey {self.cfg.es_api_key}"
        elif self.cfg.es_user:
            token = base64.b64encode(
                f"{self.cfg.es_user}:{self.cfg.es_pass or ''}".encode()
            ).decode()
            h["Authorization"] = f"Basic {token}"
        return h

    def _search(self, body: dict) -> dict:
        index = ",".join(self.cfg.es_indices)
        url = f"{self.cfg.es_url.rstrip('/')}/{index}/_search"
        try:
            r = requests.post(url, json=body, headers=self._headers(), timeout=30)
            r.raise_for_status()
            return r.json()
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            detail = (e.response.text[:300] if e.response is not None else str(e))
            raise ESError(f"ES HTTP {status}: {detail}", status=status) from e
        except requests.RequestException as e:
            raise ESError(f"ES nicht erreichbar: {e}", status=None) from e

    def _range(self, start_iso: str, end_iso: str) -> dict:
        return {"range": {self.cfg.timestamp_field: {"gte": start_iso, "lt": end_iso}}}

    def aggregate_window(self, start_iso: str, end_iso: str) -> dict:
        """Aggregate für ein Zeitfenster: {total, levels, error_messages}.

        Fallback-Leiter bei 4xx (z.B. ungültiges Feld): volle Aggregation ->
        nur Levels -> nur total. Bei Verbindungsfehler (status None) sofort weiterreichen.
        """
        cfg = self.cfg
        q = self._range(start_iso, end_iso)
        all_err_levels = cfg.error_levels + cfg.warn_levels

        full = {
            "size": 0, "track_total_hits": True, "query": q,
            "aggs": {
                "by_level": {"terms": {"field": cfg.level_field, "size": 30}},
                "errors": {
                    "filter": {"terms": {cfg.level_field: all_err_levels}},
                    "aggs": {"top_messages": {"terms": {"field": cfg.message_field, "size": 15}}},
                },
            },
        }
        levels_only = {
            "size": 0, "track_total_hits": True, "query": q,
            "aggs": {"by_level": {"terms": {"field": cfg.level_field, "size": 30}}},
        }
        total_only = {"size": 0, "track_total_hits": True, "query": q}

        for body, note in ((full, None),
                           (levels_only, f"message_field '{cfg.message_field}' nicht aggregierbar?"),
                           (total_only, f"level_field '{cfg.level_field}' nicht aggregierbar?")):
            try:
                return self._parse(self._search(body))
            except ESError as e:
                if e.status is None or e.status >= 500:
                    raise  # Verbindungs-/Serverfehler -> nicht durch Feld-Fallback heilbar
                if note:
                    log.warning("Aggregation reduziert (%s): %s", note, e)
        # unerreichbar, aber zur Sicherheit:
        return {"total": 0, "levels": {}, "error_messages": {}}

    @staticmethod
    def _parse(resp: dict) -> dict:
        aggs = resp.get("aggregations", {})
        total = resp.get("hits", {}).get("total", {})
        total_count = total.get("value", 0) if isinstance(total, dict) else (total or 0)
        levels = {
            b["key"]: b["doc_count"]
            for b in aggs.get("by_level", {}).get("buckets", [])
        }
        err_msgs = {
            str(b["key"]): b["doc_count"]
            for b in aggs.get("errors", {}).get("top_messages", {}).get("buckets", [])
        }
        return {"total": total_count, "levels": levels, "error_messages": err_msgs}
