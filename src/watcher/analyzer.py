"""LLM-Eskalation (Anthropic) — nur wenn das Regel-Gate ausgelöst hat.

Strukturierte Ausgabe via Tool-Use (erzwungen), damit das Ergebnis verlässlich
maschinenlesbar ist. Ohne ANTHROPIC_API_KEY degradiert der Hybrid sauber auf
rein regelbasiertes Melden.
"""
from __future__ import annotations

import json

_TOOL = {
    "name": "report_assessment",
    "description": "Melde die Beurteilung der Log-Auffälligkeit strukturiert zurück.",
    "input_schema": {
        "type": "object",
        "properties": {
            "anomalous": {"type": "boolean", "description": "Wirklich auffällig/handlungsbedürftig?"},
            "severity": {"type": "string", "enum": ["low", "medium", "high"]},
            "summary": {"type": "string", "description": "1-3 Sätze, was los ist."},
            "suspected_cause": {"type": "string", "description": "Vermutete Ursache (oder 'unklar')."},
            "recommended_action": {"type": "string", "description": "Konkreter nächster Schritt."},
        },
        "required": ["anomalous", "severity", "summary"],
    },
}

_SYSTEM = (
    "Du bist ein nüchterner SRE-Assistent, der Log-Aggregate eines Homelab-Stacks bewertet. "
    "Du bekommst Zähl-Aggregate für ein aktuelles Zeitfenster, das Vorfenster (Baseline) und "
    "die bereits ausgelösten Heuristik-Signale. Entscheide, ob das eine ECHTE, handlungs"
    "bedürftige Auffälligkeit ist (anomalous=true) oder erwartbares Rauschen. Sei konservativ: "
    "im Zweifel anomalous=false. Fasse knapp und konkret zusammen. Du siehst nur Aggregate/Zähler "
    "und Message-Templates (keine Rohlogs)."
)


def assess(cfg, current, baseline, signals) -> dict:
    """Gibt {anomalous, severity, summary, suspected_cause, recommended_action, llm_used} zurück."""
    payload = {
        "window_hours": cfg.window_hours,
        "triggered_signals": [
            {"kind": s.kind, "severity_hint": s.severity_hint, "detail": s.detail} for s in signals
        ],
        "current_window": current,
        "baseline_window": baseline,
    }

    if not cfg.anthropic_api_key:
        # Hybrid degradiert sauber: ohne LLM melden wir rein regelbasiert.
        from .rules import overall_severity
        return {
            "anomalous": True,
            "severity": overall_severity(signals),
            "summary": "Regelbasierte Auffälligkeit (LLM übersprungen: kein ANTHROPIC_API_KEY).",
            "suspected_cause": "unklar",
            "recommended_action": "Logs in Kibana prüfen.",
            "llm_used": False,
        }

    import anthropic  # lazy: nur nötig wenn LLM wirklich verwendet wird

    client = anthropic.Anthropic(api_key=cfg.anthropic_api_key)
    msg = client.messages.create(
        model=cfg.model,
        max_tokens=cfg.max_tokens,
        system=_SYSTEM,
        tools=[_TOOL],
        tool_choice={"type": "tool", "name": "report_assessment"},
        messages=[{
            "role": "user",
            "content": "Bewerte diese Log-Aggregate:\n\n" + json.dumps(payload, ensure_ascii=False, indent=2),
        }],
    )
    for block in msg.content:
        if getattr(block, "type", None) == "tool_use" and block.name == "report_assessment":
            result = dict(block.input)
            result["llm_used"] = True
            return result

    # tool_choice erzwingt eigentlich einen Tool-Call; Fallback konservativ.
    return {"anomalous": False, "severity": "low",
            "summary": "LLM lieferte keine strukturierte Antwort.", "llm_used": True}
