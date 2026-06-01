"""Elasticsearch-Aggregat-Abfragen (ausschließlich lesend, size=0)."""
from __future__ import annotations

import base64

import requests


class ESError(Exception):
    pass


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
        except requests.RequestException as e:
            raise ESError(f"ES-Anfrage fehlgeschlagen: {e}") from e

    def aggregate_window(self, start_iso: str, end_iso: str) -> dict:
        """Aggregate für ein Zeitfenster: {total, levels, error_messages}."""
        cfg = self.cfg
        all_err_levels = cfg.error_levels + cfg.warn_levels
        body = {
            "size": 0,
            "track_total_hits": True,
            "query": {"range": {cfg.timestamp_field: {"gte": start_iso, "lt": end_iso}}},
            "aggs": {
                "by_level": {"terms": {"field": cfg.level_field, "size": 30}},
                "errors": {
                    "filter": {"terms": {cfg.level_field: all_err_levels}},
                    "aggs": {"top_messages": {"terms": {"field": cfg.message_field, "size": 15}}},
                },
            },
        }
        return self._parse(self._search(body))

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
