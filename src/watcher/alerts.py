"""Aufbau des Alert-Dokuments für die ES-Indizierung (Kibana-Historie)."""
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
