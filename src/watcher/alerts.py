"""Aufbau der Dokumente für die ES-Indizierung (Kibana-Historie): Alerts und Zyklus-Status."""
from __future__ import annotations


def alert_index_name(prefix: str, now) -> str:
    """Monatlicher Index, z.B. log-watcher-alerts-2026.06."""
    return f"{prefix}-{now.strftime('%Y.%m')}"


def build_alert_doc(assessment, signals, current, baseline, cfg, ts_iso, signature, emailed) -> dict:
    """Ein flaches, Kibana-freundliches Dokument.

    Wichtig: top_error_messages als ARRAY von {message,count} (nicht als Objekt mit
    Message-Text als Feldname) — sonst Mapping-Explosion / ungültige Feldnamen.
    """
    return {
        "@timestamp": ts_iso,
        "target": getattr(cfg, "name", "default"),
        "severity": assessment.get("severity"),
        "summary": assessment.get("summary"),
        "suspected_cause": assessment.get("suspected_cause"),
        "recommended_action": assessment.get("recommended_action"),
        "llm_used": bool(assessment.get("llm_used")),
        "emailed": bool(emailed),
        "signature": signature,
        "monitored_indices": list(cfg.es_indices),
        "window_hours": cfg.window_hours,
        "signals": [
            {"kind": s.kind, "severity_hint": s.severity_hint, "detail": s.detail} for s in signals
        ],
        "window": {
            "total": current["total"],
            "levels": current["levels"],  # kontrollierte Keys (Error/Warning/…) -> Objekt ok
            "top_error_messages": [
                {"message": m, "count": c}
                for m, c in list(current.get("error_messages", {}).items())[:10]
            ],
        },
        "baseline": {"total": baseline["total"], "levels": baseline["levels"]},
    }


def build_cycle_doc(cfg, now, duration_s: float, summary, error) -> dict:
    """Zyklus-Status eines Targets als ECS-Dokument (Index ``log-watcher-cycles-*``, S5-017).

    summary: Rückgabe von run_cycle ({result, signals, window_total}) oder None, wenn der Zyklus
    scheiterte; error: Grund ohne ES-Adresse (main._cycle_failure_reason) oder None.
    Signal-Arten als sortierte Menge (kontrollierte Werte), keine Details/Messages — die stehen
    in den Alerts und können PII tragen.
    """
    from . import __version__
    kinds = list((summary or {}).get("signals") or [])
    return {
        "@timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "event": {
            "kind": "event",
            "category": ["process"],
            "type": ["info"],
            "dataset": "log-watcher.cycle",
            "action": "cycle",
            "outcome": "failure" if error else "success",
            "duration": int(round(duration_s * 1_000_000_000)),   # ECS: Nanosekunden
        },
        "service": {"name": "log-watcher", "version": __version__},
        "log-watcher": {
            "target": getattr(cfg, "name", "default"),
            "result": (summary or {}).get("result") if not error else "failed",
            "signals": len(kinds),
            "signal_kinds": sorted(set(kinds)),
            "window_total": (summary or {}).get("window_total"),
            "window_hours": getattr(cfg, "window_hours", None),
            "monitored_indices": list(getattr(cfg, "es_indices", []) or []),
            "error": error,
        },
    }
