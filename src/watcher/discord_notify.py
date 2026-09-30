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

    Entschärft maskierte Links wie /[Klick hier](https://evil), aber KEINE nackten URLs:
    https://… verlinkt Discord trotzdem. Text, der aus Angreifer-kontrollierten URL-Pfaden
    stammen kann, gehört deshalb in einen Code-Zaun (code_block/code_span).
    """
    if not text:
        return text
    for ch in _MD_META:
        text = text.replace(ch, "\\" + ch)
    return text


_FENCE_OVERHEAD = len("```\n\n```")


def code_block(text: str, limit: int) -> str:
    """Nicht vertrauenswürdigen Text als Discord-Codeblock (wie der Digest).

    Im Code-Zaun rendert Discord weder Markdown noch Links — auch ein nacktes https://… aus
    einem angefragten Pfad (/.env/https://phish.example) bleibt unklickbar. Backticks werden
    vorher zu ' (ein ``` im Text würde den Zaun sprengen), gekürzt wird VOR dem Umzäunen, damit
    das Feldlimit nie den schließenden Zaun abschneidet.
    """
    body = str(text or "").replace("`", "'")[:max(0, limit - _FENCE_OVERHEAD)]
    return f"```\n{body}\n```"


def code_span(text: str, limit: int) -> str:
    """Wie code_block, einzeilig als Inline-Code; mehrzeiliger Text fällt auf den Codeblock zurück."""
    body = str(text or "").replace("`", "'")
    if "\n" in body or not body.strip():
        return code_block(body, limit)
    return f"`{body[:max(0, limit - 2)]}`"


def build_alert_payload(subject: str, assessment, signals, current, baseline, cfg) -> dict:
    sev = str(assessment.get("severity", "low"))
    # detail kommt aus Logs/URL-Pfaden (untrusted) -> Codeblock: kein Markdown, keine Links, auch
    # keine nackten https://-URLs. kind/severity_hint sind interne Konstanten.
    sig_lines = "\n".join(f"[{s.severity_hint}] {s.kind}: {s.detail}" for s in signals)
    fields = [{"name": "Signale", "value": code_block(sig_lines, 1024) if signals else "—"}]
    if assessment.get("suspected_cause"):
        fields.append({"name": "Vermutete Ursache", "value": code_span(assessment["suspected_cause"], 1024)})
    if assessment.get("recommended_action"):
        fields.append({"name": "Empfohlene Aktion", "value": code_span(assessment["recommended_action"], 1024)})
    fields.append({"name": "Fenster", "value":
                   f"total {current['total']} · Baseline {baseline['total']} · "
                   f"LLM {'ja' if assessment.get('llm_used') else 'nein'}"[:1024]})
    embed = {
        "title": subject[:256],
        # summary rendert Markdown und enthält bei Security-Signalen die Details wörtlich -> umzäunen.
        "description": code_block(assessment.get("summary"), 4096) if assessment.get("summary") else "",
        "color": _COLOR.get(sev, 0x6C757D),
        "fields": fields[:25],
        # Target-Name im Footer: macht die Quelle eindeutig, wenn mehrere ES-Instanzen
        # identische Index-Namen haben (prod vs. dev, beide rookhub-logs-*). Die ES-URL
        # (interne LAN-Adresse) gehört nicht in einen Drittanbieter-Kanal.
        "footer": {"text": str(cfg.name)[:2048]},
    }
    payload = {"embeds": [embed]}
    # HIGH pingt den konfigurierten Benutzer — als content (Embeds pingen nie) und mit
    # allowed_mentions, die NUR genau diese ID erlauben (parse bleibt leer): ein
    # "@everyone"/"<@…>" aus Log-Text kann also weiterhin niemanden anpingen, und
    # post() lässt dieses explizite allowed_mentions dank setdefault unangetastet.
    mention = str(getattr(cfg, "discord_mention_user_id", "") or "")
    if sev == "high" and mention:
        payload["content"] = f"<@{mention}>"
        payload["allowed_mentions"] = {"parse": [], "users": [mention]}
    return payload


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
