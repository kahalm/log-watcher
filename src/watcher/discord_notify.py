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


def build_alert_payload(subject: str, assessment, signals, current, baseline, cfg) -> dict:
    sev = str(assessment.get("severity", "low"))
    sig_text = "\n".join(f"[{s.severity_hint}] {s.kind}: {s.detail}" for s in signals) or "—"
    fields = [{"name": "Signale", "value": sig_text[:1024]}]
    if assessment.get("suspected_cause"):
        fields.append({"name": "Vermutete Ursache", "value": str(assessment["suspected_cause"])[:1024]})
    if assessment.get("recommended_action"):
        fields.append({"name": "Empfohlene Aktion", "value": str(assessment["recommended_action"])[:1024]})
    fields.append({"name": "Fenster", "value":
                   f"total {current['total']} · Baseline {baseline['total']} · "
                   f"LLM {'ja' if assessment.get('llm_used') else 'nein'}"[:1024]})
    embed = {
        "title": subject[:256],
        "description": (assessment.get("summary") or "")[:4096],
        "color": _COLOR.get(sev, 0x6C757D),
        "fields": fields[:25],
    }
    return {"embeds": [embed]}


def post(webhook_url: str, payload: dict) -> int:
    """POSTet ein Webhook-Payload. Wirft bei HTTP-/Netzfehler (Caller fängt best-effort)."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": _UA}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        return getattr(r, "status", 0)


def post_text(webhook_url: str, content: str) -> int:
    return post(webhook_url, {"content": content[:2000]})
