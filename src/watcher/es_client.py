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

        by_index = {"by_index": {"terms": {"field": "_index", "size": 50}}}
        full = {
            "size": 0, "track_total_hits": True, "query": q,
            "aggs": {
                "by_level": {"terms": {"field": cfg.level_field, "size": 30}},
                **by_index,
                "errors": {
                    "filter": {"terms": {cfg.level_field: all_err_levels}},
                    "aggs": {"top_messages": {"terms": {"field": cfg.message_field, "size": 15}}},
                },
            },
        }
        levels_only = {
            "size": 0, "track_total_hits": True, "query": q,
            "aggs": {"by_level": {"terms": {"field": cfg.level_field, "size": 30}}, **by_index},
        }
        total_only = {"size": 0, "track_total_hits": True, "query": q}

        for body, note in ((full, None),
                           (levels_only, "Fallback ohne Top-Messages (Feld nicht aggregierbar?)"),
                           (total_only, "Fallback nur Gesamtzahl (Level-Aggregation nicht möglich?)")):
            try:
                return self._parse(self._search(body))
            except ESError as e:
                if e.status is None or e.status >= 500:
                    raise  # Verbindungs-/Serverfehler -> nicht durch Feld-Fallback heilbar
                if note:
                    log.warning("Aggregation reduziert (%s): %s", note, e)
        # unerreichbar, aber zur Sicherheit:
        return {"total": 0, "levels": {}, "error_messages": {}}

    def fetch_samples(self, start_iso: str, end_iso: str, size: int, field: str) -> list:
        """Jüngste Fehler-Logzeilen (nur das angegebene Feld) als LLM-Kontext (Feature 14)."""
        cfg = self.cfg
        body = {
            "size": max(0, size),
            "query": {"bool": {
                "must": [{"range": {cfg.timestamp_field: {"gte": start_iso, "lt": end_iso}}}],
                "filter": [{"terms": {cfg.level_field: cfg.error_levels}}],
            }},
            "sort": [{cfg.timestamp_field: {"order": "desc"}}],
            "_source": [field],
        }
        try:
            resp = self._search(body)
        except ESError:
            return []  # Samples sind optional -> nie den Zyklus killen
        out = []
        for h in resp.get("hits", {}).get("hits", []):
            val = (h.get("_source") or {}).get(field)
            if val:
                out.append(str(val)[:300])
        return out

    def count(self, index: str, query: dict) -> int:
        """_count gegen ein (ggf. nicht existierendes) Index-Pattern. 0 bei Fehler/leer."""
        url = f"{self.cfg.es_url.rstrip('/')}/{index}/_count"
        try:
            r = requests.post(url, json={"query": query}, headers=self._headers(), timeout=15)
            if r.status_code == 404:
                return 0
            r.raise_for_status()
            return int(r.json().get("count", 0))
        except (requests.RequestException, ValueError):
            return 0

    def per_index_counts(self, start_iso: str, end_iso: str) -> dict:
        """Nur Doc-Counts je Index für ein Fenster (leichtgewichtig, für die Index-Stille-Prüfung).

        {index_name: count}. Bei 4xx (z.B. Feld nicht aggregierbar) leeres Dict;
        Verbindungs-/Serverfehler (status None / >=500) werden weitergereicht.
        """
        body = {
            "size": 0, "track_total_hits": False,
            "query": self._range(start_iso, end_iso),
            "aggs": {"by_index": {"terms": {"field": "_index", "size": 50}}},
        }
        try:
            resp = self._search(body)
        except ESError as e:
            if e.status is None or e.status >= 500:
                raise
            log.warning("per_index_counts reduziert (Feld nicht aggregierbar?): %s", e)
            return {}
        buckets = resp.get("aggregations", {}).get("by_index", {}).get("buckets", [])
        return {b["key"]: b["doc_count"] for b in buckets}

    def security_window(self, start_iso: str, end_iso: str) -> dict:
        """Aggregiert HTTP-Zugriffslogs des Fensters für die Security-Heuristik.

        Scope: Dokumente mit vorhandenem Statuscode-Feld (= Zugriffslogs, vgl. `request`-Tag).
        Liefert {total_requests, suspicious:{count,paths,ips}, by_ip:{ip:{total,c4xx,auth_fail,
        distinct_paths}}}. Bei 4xx (Feld nicht aggregierbar) leeres Ergebnis statt Zyklus-Abbruch;
        Verbindungs-/Serverfehler werden weitergereicht.
        """
        from .security import DEFAULT_PATH_TOKENS
        cfg = self.cfg
        status_f, path_f, ip_f = cfg.security_status_field, cfg.security_path_field, cfg.security_ip_field
        tokens = cfg.security_path_tokens or DEFAULT_PATH_TOKENS

        suspicious_should = [
            {"wildcard": {path_f: {"value": f"*{t}*", "case_insensitive": True}}} for t in tokens
        ]
        aggs = {
            "by_ip": {
                "terms": {"field": ip_f, "size": max(1, cfg.security_top_ips)},
                "aggs": {
                    "c4xx": {"filter": {"range": {status_f: {"gte": 400, "lt": 500}}}},
                    "auth_fail": {"filter": {"terms": {status_f: [401, 403]}}},
                    "distinct_paths": {"cardinality": {"field": path_f}},
                },
            },
        }
        if suspicious_should:
            # Treffer zusätzlich auf 4xx/5xx einschränken: ein echtes „Abklopfen" trifft Pfade,
            # die es auf dieser API nicht gibt (→ 404). So matchen legitime Endpoints, die zufällig
            # ein Token als Teilstring enthalten (z.B. .../config), nicht (die antworten 2xx).
            aggs["suspicious"] = {
                "filter": {"bool": {
                    "must": [{"range": {status_f: {"gte": 400}}}],
                    "should": suspicious_should, "minimum_should_match": 1,
                }},
                "aggs": {
                    "paths": {"terms": {"field": path_f, "size": 10}},
                    "ips": {"terms": {"field": ip_f, "size": 10}},
                },
            }
        body = {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"filter": [self._range(start_iso, end_iso), {"exists": {"field": status_f}}]}},
            "aggs": aggs,
        }
        try:
            resp = self._search(body)
        except ESError as e:
            if e.status is None or e.status >= 500:
                raise
            log.warning("security_window reduziert (Feld nicht aggregierbar?): %s", e)
            return {"total_requests": 0, "suspicious": {"count": 0, "paths": {}, "ips": {}}, "by_ip": {}}
        return self._parse_security(resp)

    @staticmethod
    def _parse_security(resp: dict) -> dict:
        aggs = resp.get("aggregations", {})
        total = resp.get("hits", {}).get("total", {})
        total_count = total.get("value", 0) if isinstance(total, dict) else (total or 0)
        susp_agg = aggs.get("suspicious", {})
        suspicious = {
            "count": int(susp_agg.get("doc_count", 0)),
            "paths": {str(b["key"]): b["doc_count"] for b in susp_agg.get("paths", {}).get("buckets", [])},
            "ips": {str(b["key"]): b["doc_count"] for b in susp_agg.get("ips", {}).get("buckets", [])},
        }
        by_ip = {}
        for b in aggs.get("by_ip", {}).get("buckets", []):
            by_ip[str(b["key"])] = {
                "total": b.get("doc_count", 0),
                "c4xx": int(b.get("c4xx", {}).get("doc_count", 0)),
                "auth_fail": int(b.get("auth_fail", {}).get("doc_count", 0)),
                "distinct_paths": int(b.get("distinct_paths", {}).get("value", 0)),
            }
        return {"total_requests": total_count, "suspicious": suspicious, "by_ip": by_ip}

    def ensure_alert_template(self, prefix: str) -> None:
        """Index-Template für die Alert-Indizes: replicas=0 (Single-Node bleibt green)."""
        name = f"{prefix}-template"
        body = {"index_patterns": [f"{prefix}-*"], "template": {"settings": {"number_of_replicas": 0}}}
        url = f"{self.cfg.es_url.rstrip('/')}/_index_template/{name}"
        try:
            r = requests.put(url, json=body, headers=self._headers(), timeout=30)
            r.raise_for_status()
        except requests.RequestException as e:
            raise ESError(f"Alert-Index-Template fehlgeschlagen: {e}") from e

    def index_alert(self, doc: dict, index: str) -> None:
        """Schreibt ein Alert-Dokument (für die Kibana-Historie)."""
        url = f"{self.cfg.es_url.rstrip('/')}/{index}/_doc"
        try:
            r = requests.post(url, json=doc, headers=self._headers(), timeout=30)
            r.raise_for_status()
        except requests.RequestException as e:
            raise ESError(f"Alert-Indizierung fehlgeschlagen: {e}") from e

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
        per_index = {
            str(b["key"]): b["doc_count"]
            for b in aggs.get("by_index", {}).get("buckets", [])
        }
        return {"total": total_count, "levels": levels, "error_messages": err_msgs, "per_index": per_index}
