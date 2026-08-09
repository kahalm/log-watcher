"""Discord-Webhook als Alert-Kanal (Feature: Discord). Reines HTTP, kein discord.py."""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from . import __version__

log = logging.getLogger("log-watcher")

_COLOR = {"low": 0x6C757D, "medium": 0xE0A800, "high": 0xDC3545}
# Discord/Cloudflare blockt den Standard-urllib-User-Agent (403, Cloudflare 1010) -> eigenen setzen.
_UA = f"log-watcher/{__version__} (+https://github.com/kahalm/log-watcher)"

# Backslash MUSS zuerst escapt werden, sonst würde ein bereits vorhandenes "\" mit den
# danach eingefügten Escapes neue Sequenzen bilden und die Klammer wieder scharf machen.
_MD_META = "\\`*_[]"


def escape_markdown(text: str) -> str:
    """Escapt Discord-Markdown-Metazeichen in nicht vertrauenswürdigem Text.

    Signal-Details entstehen aus Angreifer-kontrollierten URL-Pfaden/Hostnamen — ein
    angefragter Pfad wie /[Klick hier](https://evil) würde im Embed sonst zum klickbaren
    Link und machte den Alert-Kanal selbst zur Phishing-Fläche.
    """
    if not text:
        return text
    for ch in _MD_META:
        text = text.replace(ch, "\\" + ch)
    return text


def build_alert_payload(subject: str, assessment, signals, current, baseline, cfg) -> dict:
    sev = str(assessment.get("severity", "low"))
    # detail escapen: kommt aus Logs/URL-Pfaden (untrusted); kind/severity_hint sind interne Konstanten.
    sig_text = "\n".join(f"[{s.severity_hint}] {s.kind}: {escape_markdown(s.detail)}" for s in signals) or "—"
    fields = [{"name": "Signale", "value": sig_text[:1024]}]
    if assessment.get("suspected_cause"):
        fields.append({"name": "Vermutete Ursache", "value": escape_markdown(str(assessment["suspected_cause"]))[:1024]})
    if assessment.get("recommended_action"):
        fields.append({"name": "Empfohlene Aktion", "value": escape_markdown(str(assessment["recommended_action"]))[:1024]})
    fields.append({"name": "Fenster", "value":
                   f"total {current['total']} · Baseline {baseline['total']} · "
                   f"LLM {'ja' if assessment.get('llm_used') else 'nein'}"[:1024]})
    embed = {
        "title": subject[:256],
        # summary rendert Markdown und enthält bei Security-Signalen die Details wörtlich -> escapen.
        "description": escape_markdown(assessment.get("summary") or "")[:4096],
        "color": _COLOR.get(sev, 0x6C757D),
        "fields": fields[:25],
        # Target-Name + ES-URL im Footer: macht die Quelle eindeutig, wenn mehrere
        # ES-Instanzen identische Index-Namen haben (prod vs. dev, beide rookhub-logs-*).
        "footer": {"text": f"{cfg.name} · {cfg.es_url}"[:2048]},
    }
    return {"embeds": [embed]}


def post(webhook_url: str, payload: dict) -> int:
    """POSTet ein Webhook-Payload. Wirft bei HTTP-/Netzfehler (Caller fängt best-effort)."""
    # Mentions zentral totlegen: ein "@everyone" in Log-Text/Digest darf nie pingen.
    payload.setdefault("allowed_mentions", {"parse": []})
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": _UA}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        return getattr(r, "status", 0)


def post_text(webhook_url: str, content: str) -> int:
    return post(webhook_url, {"content": content[:2000]})
