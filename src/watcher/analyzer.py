"""LLM-Eskalation (Anthropic) — nur wenn das Regel-Gate ausgelöst hat.

Strukturierte Ausgabe via Tool-Use (erzwungen), damit das Ergebnis verlässlich
maschinenlesbar ist. Ohne ANTHROPIC_API_KEY degradiert der Hybrid sauber auf
rein regelbasiertes Melden.
"""
from __future__ import annotations

import json
import logging

log = logging.getLogger("log-watcher")

# Obergrenze fuer einen LLM-Aufruf. Er laeuft synchron in der einzigen Schleife: mit den
# SDK-Standards (600 s, 2 Wiederholungen) hielt ein haengender Endpunkt alle uebrigen Targets und
# den Heartbeat bis zu ~30 min an. 60 s x 2 Versuche bleiben unter der Healthcheck-Schwelle (180 s);
# was laenger braucht, bricht ab und wird regelbasiert gemeldet.
LLM_TIMEOUT_SECONDS = 60
LLM_MAX_RETRIES = 1

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
    "im Zweifel anomalous=false. Fasse knapp und konkret zusammen. Du siehst Aggregate/Zähler, "
    "Message-Templates und ggf. einige bereits REDIGIERTE Beispiel-Logzeilen (PII/Secrets entfernt). "
    "Sicherheitssignale (suspicious_requests, api_scan, auth_bruteforce) bedeuten, dass ein Client die "
    "API systematisch abklopft (Scanner-Pfade, Pfad-Enumeration, Brute-Force) — das ist IMMER auffällig "
    "(anomalous=true, severity=high); nenne in der Empfehlung das Blocken der Quell-IP."
)


def rule_based(signals, summary: str, llm_error: str | None = None,
               llm_error_kind: str | None = None) -> dict:
    """Bewertung allein aus den Regeln — der Rückfallweg ohne LLM."""
    from .rules import overall_severity
    result = {
        "anomalous": True,
        "severity": overall_severity(signals),
        "summary": summary,
        "suspected_cause": "unklar",
        "recommended_action": "Logs in Kibana prüfen.",
        "llm_used": False,
        "llm_tokens": 0,
    }
    if llm_error:
        result["llm_error"] = llm_error
        result["llm_error_kind"] = llm_error_kind or "sonstiges"
    return result


def _sdk_error_class(name: str):
    """Fehlerklasse des anthropic-SDK, None wenn SDK oder Klasse fehlen (lazy wie in assess)."""
    try:
        import anthropic
    except ImportError:
        return None
    cls = getattr(anthropic, name, None)
    return cls if isinstance(cls, type) else None


def _is_timeout(exc: BaseException) -> bool:
    timeout_cls = _sdk_error_class("APITimeoutError")
    return isinstance(exc, TimeoutError) or (timeout_cls is not None and isinstance(exc, timeout_cls))


_GUTHABEN = ("guthaben", "Anthropic-Guthaben erschöpft")
_SCHLUESSEL = ("schluessel", "API-Schlüssel abgelehnt")
_DROSSELUNG = ("drosselung", "API drosselt oder ist überlastet")


def classify_llm_error(exc: BaseException) -> tuple[str, str]:
    """(Art, Klartext) eines gescheiterten LLM-Aufrufs.

    Die Art entscheidet, was zu TUN ist, und genau das soll in der Warnung stehen: leeres
    Guthaben will aufgeladen werden, ein abgelehnter Schlüssel ersetzt, eine Drosselung
    ausgesessen. Zuerst entscheiden SDK-Typ und HTTP-Status (anthropic.APIStatusError):
    401 = Schlüssel, 429/529 = Drosselung — ein neuer SDK-Major mit anderem Ausnahmetext ändert
    daran nichts. Der Text ist nur Zusatz: bei einem Status-Fehler für das Guthaben (die
    Fehlerklasse BadRequestError deckt beides ab — Guthaben UND echte Anfragefehler, den
    Hinweis trägt der Antwort-Body), bei Fehlern ohne Status für alles. Eine Zeitueberschreitung
    (LLM_TIMEOUT_SECONDS) zaehlt als Drosselung: der Endpunkt ist erreichbar, antwortet aber
    nicht rechtzeitig.
    """
    if _is_timeout(exc):
        return "drosselung", "API antwortet nicht rechtzeitig (Zeitüberschreitung)"
    text = str(exc)
    low = text.lower()
    billing = ("credit balance" in low or "plans & billing" in low or "billing" in low
               or getattr(exc, "type", None) == "billing_error")
    status_cls = _sdk_error_class("APIStatusError")
    status = getattr(exc, "status_code", None) if status_cls and isinstance(exc, status_cls) else None
    if status == 401:
        return _SCHLUESSEL
    if status in (429, 529):
        return _DROSSELUNG
    if billing:
        return _GUTHABEN
    if status is None:
        # Ohne HTTP-Status bleibt nur der Text. Mit Status zaehlen Zahlen im Text nicht:
        # "prompt is too long: 240100 tokens" (400) ist kein abgelehnter Schluessel.
        if "authentication" in low or "invalid x-api-key" in low or "401" in low:
            return _SCHLUESSEL
        if "rate limit" in low or "429" in low or "overloaded" in low:
            return _DROSSELUNG
    return "sonstiges", text.strip().splitlines()[0][:200] if text.strip() else exc.__class__.__name__


def assess(cfg, current, baseline, signals, samples=None, use_llm=None) -> dict:
    """Gibt {anomalous, severity, summary, …, llm_used, llm_tokens} zurück.

    use_llm erzwingt/verhindert den LLM-Aufruf (z.B. Budget erschöpft -> rein
    regelbasiert). samples: bereits redigierte Beispiel-Logzeilen (Feature 14).
    """
    if use_llm is None:
        use_llm = bool(cfg.anthropic_api_key)

    if not use_llm:
        # Hybrid degradiert sauber: ohne LLM (kein Key / Budget erschöpft) regelbasiert melden.
        return rule_based(signals, "Regelbasierte Auffälligkeit (LLM übersprungen).")

    payload = {
        "window_hours": cfg.window_hours,
        "triggered_signals": [
            {"kind": s.kind, "severity_hint": s.severity_hint, "detail": s.detail} for s in signals
        ],
        "current_window": current,
        "baseline_window": baseline,
        "sample_log_lines": samples or [],
    }

    import anthropic  # lazy: nur nötig wenn LLM wirklich verwendet wird

    client = anthropic.Anthropic(api_key=cfg.anthropic_api_key,
                                 timeout=LLM_TIMEOUT_SECONDS, max_retries=LLM_MAX_RETRIES)
    try:
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
    except Exception as e:  # noqa: BLE001
        # Ein toter LLM-Aufruf darf den Zyklus NICHT abbrechen: vorher flog die Ausnahme bis in
        # die Hauptschleife, der Alarm blieb aus, und der Wachhund schwieg genau dann, wenn das
        # Regel-Gate schon angeschlagen hatte (beobachtet 2026-09-06/07: 84 Zyklen am Stueck,
        # Guthaben leer). Jetzt: regelbasiert weitermachen und den Ausfall benennen — der
        # Aufrufer warnt darueber und unterdrueckt die Alles-in-Ordnung-Meldung.
        kind, reason = classify_llm_error(e)
        log.error("LLM-Aufruf fehlgeschlagen (%s): %s", kind, reason)
        return rule_based(signals, f"Regelbasierte Auffälligkeit — LLM nicht verfügbar ({reason}).",
                          llm_error=reason, llm_error_kind=kind)
    usage = getattr(msg, "usage", None)
    tokens = 0
    if usage is not None:
        tokens = (getattr(usage, "input_tokens", 0) or 0) + (getattr(usage, "output_tokens", 0) or 0)
        log.info("LLM-Verbrauch: in=%s out=%s tokens (model=%s)",
                 getattr(usage, "input_tokens", "?"), getattr(usage, "output_tokens", "?"), cfg.model)

    for block in msg.content:
        if getattr(block, "type", None) == "tool_use" and block.name == "report_assessment":
            result = dict(block.input)
            result["llm_used"] = True
            result["llm_tokens"] = tokens
            return result

    # tool_choice erzwingt eigentlich einen Tool-Call; Fallback konservativ.
    return {"anomalous": False, "severity": "low",
            "summary": "LLM lieferte keine strukturierte Antwort.", "llm_used": True, "llm_tokens": tokens}
