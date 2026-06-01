"""E-Mail-Versand via SMTP + Aufbereitung des Mail-Texts."""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage


def build_email_body(assessment, signals, current, baseline, cfg) -> str:
    lines = [assessment.get("summary", ""), ""]
    lines.append(f"Schweregrad: {assessment.get('severity', '?')}")
    if assessment.get("suspected_cause"):
        lines.append(f"Vermutete Ursache: {assessment['suspected_cause']}")
    if assessment.get("recommended_action"):
        lines.append(f"Empfohlene Aktion: {assessment['recommended_action']}")
    lines.append(f"LLM verwendet: {'ja' if assessment.get('llm_used') else 'nein (regelbasiert)'}")
    lines.append("")
    lines.append("Ausgelöste Heuristik-Signale:")
    for s in signals:
        lines.append(f"  - [{s.severity_hint}] {s.kind}: {s.detail}")
    lines.append("")
    lines.append(f"Aktuelles Fenster ({cfg.window_hours}h): total={current['total']} levels={current['levels']}")
    lines.append(f"Vorfenster:                total={baseline['total']} levels={baseline['levels']}")
    if current.get("error_messages"):
        lines.append("")
        lines.append("Top Fehler-Messages (aktuelles Fenster):")
        for m, c in list(current["error_messages"].items())[:10]:
            lines.append(f"  {c:>4}x  {m}")
    lines.append("")
    lines.append("— log-watcher")
    return "\n".join(lines)


def send_email(cfg, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.smtp_from
    msg["To"] = ", ".join(cfg.smtp_to)
    msg.set_content(body)
    with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=30) as s:
        if cfg.smtp_tls:
            s.starttls(context=ssl.create_default_context())
        if cfg.smtp_user:
            s.login(cfg.smtp_user, cfg.smtp_pass or "")
        s.send_message(msg)
