"""E-Mail-Versand via SMTP + Aufbereitung (Plaintext + HTML)."""
from __future__ import annotations

import html as _html
import smtplib
import ssl
from email.message import EmailMessage

_SEV_COLOR = {"low": "#6c757d", "medium": "#e0a800", "high": "#dc3545"}


def build_email_body(assessment, signals, current, baseline, cfg) -> str:
    """Plaintext-Variante (Fallback für Clients ohne HTML)."""
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


def build_email_html(assessment, signals, current, baseline, cfg) -> str:
    """HTML-Variante mit Farb-Badges + Tabellen. Dynamische Werte werden escaped."""
    esc = _html.escape
    sev = str(assessment.get("severity", "low"))
    color = _SEV_COLOR.get(sev, "#6c757d")

    def badge(text, bg):
        return (f'<span style="display:inline-block;padding:1px 7px;border-radius:10px;'
                f'background:{bg};color:#fff;font-size:11px;font-weight:700;'
                f'text-transform:uppercase">{esc(str(text))}</span>')

    meta_rows = ""
    for label, key in (("Vermutete Ursache", "suspected_cause"), ("Empfohlene Aktion", "recommended_action")):
        if assessment.get(key):
            meta_rows += (f'<tr><td style="padding:2px 10px 2px 0;color:#666">{label}</td>'
                          f'<td style="padding:2px 0">{esc(str(assessment[key]))}</td></tr>')
    meta_rows += (f'<tr><td style="padding:2px 10px 2px 0;color:#666">LLM</td>'
                  f'<td style="padding:2px 0">{"ja" if assessment.get("llm_used") else "nein (regelbasiert)"}</td></tr>')

    signal_items = "".join(
        f'<li style="margin:3px 0">{badge(s.severity_hint, _SEV_COLOR.get(s.severity_hint, "#6c757d"))} '
        f'<b>{esc(s.kind)}</b>: {esc(s.detail)}</li>'
        for s in signals
    ) or "<li>—</li>"

    keys = list(dict.fromkeys(list(current["levels"].keys()) + list(baseline["levels"].keys())))
    level_rows = "".join(
        f'<tr><td style="padding:3px 10px;border-top:1px solid #eee">{esc(str(k))}</td>'
        f'<td style="padding:3px 10px;border-top:1px solid #eee;text-align:right">{current["levels"].get(k, 0)}</td>'
        f'<td style="padding:3px 10px;border-top:1px solid #eee;text-align:right;color:#888">{baseline["levels"].get(k, 0)}</td></tr>'
        for k in keys
    ) or '<tr><td colspan="3" style="padding:3px 10px">—</td></tr>'

    err_rows = "".join(
        f'<tr><td style="padding:3px 10px;border-top:1px solid #eee;text-align:right;white-space:nowrap">{c}×</td>'
        f'<td style="padding:3px 10px;border-top:1px solid #eee">{esc(str(m))}</td></tr>'
        for m, c in list(current.get("error_messages", {}).items())[:10]
    ) or '<tr><td colspan="2" style="padding:3px 10px">—</td></tr>'

    return f"""<!doctype html>
<html><body style="margin:0;background:#fff;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#1b1b1b">
  <div style="max-width:680px;margin:0 auto;padding:16px">
    <div style="border-left:6px solid {color};background:#f7f7f7;padding:10px 14px;border-radius:4px">
      <div style="font-size:12px;color:{color};font-weight:700;text-transform:uppercase">Schweregrad: {esc(sev)}</div>
      <div style="font-size:16px;margin-top:5px">{esc(str(assessment.get("summary", "")))}</div>
    </div>
    <table style="margin-top:12px;font-size:14px;border-collapse:collapse">{meta_rows}</table>
    <h4 style="margin:18px 0 6px">Ausgelöste Signale</h4>
    <ul style="margin:0;padding-left:18px;font-size:14px">{signal_items}</ul>
    <h4 style="margin:18px 0 6px">Fenster ({esc(str(cfg.window_hours))}h) vs. Baseline</h4>
    <table style="border-collapse:collapse;font-size:13px;min-width:320px">
      <tr style="background:#f0f0f0"><th style="padding:4px 10px;text-align:left">Level</th>
        <th style="padding:4px 10px;text-align:right">Aktuell</th>
        <th style="padding:4px 10px;text-align:right">Baseline</th></tr>
      {level_rows}
      <tr><td style="padding:4px 10px;border-top:2px solid #ddd;font-weight:700">Σ total</td>
        <td style="padding:4px 10px;border-top:2px solid #ddd;text-align:right;font-weight:700">{current["total"]}</td>
        <td style="padding:4px 10px;border-top:2px solid #ddd;text-align:right;color:#888">{baseline["total"]}</td></tr>
    </table>
    <h4 style="margin:18px 0 6px">Top Fehler-Messages (aktuelles Fenster)</h4>
    <table style="border-collapse:collapse;font-size:13px;min-width:320px">{err_rows}</table>
    <div style="margin-top:18px;color:#999;font-size:12px">— log-watcher</div>
  </div>
</body></html>"""


def send_email(cfg, subject: str, text_body: str, html_body: "str | None" = None) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.smtp_from
    msg["To"] = ", ".join(cfg.smtp_to)
    msg.set_content(text_body)                       # Plaintext-Fallback
    if html_body:
        msg.add_alternative(html_body, subtype="html")
    with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=30) as s:
        if cfg.smtp_tls:
            s.starttls(context=ssl.create_default_context())
        if cfg.smtp_user:
            s.login(cfg.smtp_user, cfg.smtp_pass or "")
        s.send_message(msg)
