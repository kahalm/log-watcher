"""Periodischer Digest (Feature 4): „alles ruhig" / Zusammenfassung je Target."""
from __future__ import annotations

import html as _html
from datetime import timedelta


def _count_levels(levels: dict, names) -> int:
    return sum(levels.get(n, 0) for n in names)


def target_summary(cfg, es, period_seconds: float, now, iso) -> dict:
    start = now - timedelta(seconds=period_seconds)
    agg = es.aggregate_window(iso(start), iso(now))
    alerts = es.count(
        f"{cfg.alert_index_prefix}-*",
        {"bool": {"must": [
            {"range": {"@timestamp": {"gte": iso(start), "lt": iso(now)}}},
            {"term": {"target": cfg.name}},
        ]}},
    )
    return {
        "name": cfg.name,
        "total": agg["total"],
        "errors": _count_levels(agg["levels"], cfg.error_levels),
        "warnings": _count_levels(agg["levels"], cfg.warn_levels),
        "alerts": alerts,
        "top_errors": list(agg.get("error_messages", {}).items())[:5],
    }


def build(summaries: list, period_days: int):
    period = "24h" if period_days == 1 else f"{period_days}d"
    total_alerts = sum(s["alerts"] for s in summaries)
    head = "alles ruhig" if total_alerts == 0 else f"{total_alerts} Alert(s)"
    subject = f"[log-watcher] Digest ({period}) — {head}"

    lines = [f"log-watcher Digest der letzten {period}:", ""]
    for s in summaries:
        lines.append(f"• {s['name']}: {s['total']} Logs · {s['errors']} Fehler · "
                     f"{s['warnings']} Warnungen · {s['alerts']} Alert(s)")
        for m, c in s["top_errors"]:
            lines.append(f"      {c:>4}x  {m}")
    text = "\n".join(lines)

    esc = _html.escape
    rows = "".join(
        f'<tr><td style="padding:3px 10px;border-top:1px solid #eee">{esc(s["name"])}</td>'
        f'<td style="padding:3px 10px;border-top:1px solid #eee;text-align:right">{s["total"]}</td>'
        f'<td style="padding:3px 10px;border-top:1px solid #eee;text-align:right">{s["errors"]}</td>'
        f'<td style="padding:3px 10px;border-top:1px solid #eee;text-align:right">{s["warnings"]}</td>'
        f'<td style="padding:3px 10px;border-top:1px solid #eee;text-align:right"><b>{s["alerts"]}</b></td></tr>'
        for s in summaries
    )
    html = f"""<!doctype html><html><body style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#1b1b1b">
  <div style="max-width:680px;margin:0 auto;padding:16px">
    <h3 style="margin:0 0 4px">log-watcher Digest <span style="color:#888;font-weight:400">({period})</span></h3>
    <div style="color:#666;margin-bottom:10px">{esc(head)}</div>
    <table style="border-collapse:collapse;font-size:13px;min-width:420px">
      <tr style="background:#f0f0f0"><th style="padding:4px 10px;text-align:left">Target</th>
        <th style="padding:4px 10px;text-align:right">Logs</th>
        <th style="padding:4px 10px;text-align:right">Fehler</th>
        <th style="padding:4px 10px;text-align:right">Warnungen</th>
        <th style="padding:4px 10px;text-align:right">Alerts</th></tr>
      {rows}
    </table>
    <div style="margin-top:18px;color:#999;font-size:12px">— log-watcher</div>
  </div></body></html>"""
    return subject, text, html
