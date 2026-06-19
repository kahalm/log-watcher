"""Security-Heuristik: erkennt systematisches „Abklopfen" der API durch Clients.

Wertet HTTP-Zugriffslogs (Requests mit http.response.status_code) eines Fensters aus
und feuert deterministische Signale, wenn jemand die API scannt/probt:

- suspicious_requests : Aufrufe auf bekannte Scanner-/Exploit-Pfade (.env, wp-admin,
                        phpMyAdmin, /.git, Pfad-Traversal, .php gegen eine .NET-API …).
- api_scan            : eine einzelne Quell-IP erzeugt viele 4xx über viele VERSCHIEDENE
                        Pfade -> Pfad-Enumeration/Fuzzing (legitime, wiederholte 404 auf
                        wenige Pfade — z.B. Bot-Endpoints — fallen dadurch NICHT auf).
- auth_bruteforce     : eine Quell-IP sammelt viele abgelehnte Auth-Antworten (401/403).

Alle drei sind „große Warnungen" (severity high). Die eigentlichen Schwellen/Felder/Tokens
sind über die Config (ENV) einstellbar; die Defaults sind bewusst konservativ, damit
normaler Betrieb keinen Fehlalarm auslöst.
"""
from __future__ import annotations

from .rules import Signal

# Signal-Arten dieses Moduls — main.py erzwingt für diese einen Alarm (LLM darf sie
# nicht „wegbeurteilen"): ein bestätigter Scan ist immer meldenswert.
SECURITY_KINDS = {"suspicious_requests", "api_scan", "auth_bruteforce"}

# Substrings (case-insensitiv) in url.path, die auf Scanner/Exploit-Versuche hindeuten.
# Bewusst auf Pfad-Signaturen beschränkt (Querystrings werden nicht geloggt). Erweiterbar
# über SECURITY_PATH_TOKENS. Die API ist .NET — `.php`/`.asp`-Pfade sind hier per se fremd.
DEFAULT_PATH_TOKENS = [
    ".env", ".git", ".aws", ".ssh", ".svn", ".htaccess", ".DS_Store",
    "wp-admin", "wp-login", "wp-content", "wp-includes", "xmlrpc.php", "wordpress", "wp-config",
    "phpmyadmin", "phpMyAdmin", "/pma/", "adminer", "/mysql/",
    ".php", ".asp", ".aspx", ".jsp", ".cgi", "cgi-bin",
    "/vendor/", "/server-status", "/server-info",
    "/actuator", "/solr/", "/struts", "/jenkins", "/hudson", "/owa/", "/autodiscover",
    "/boaform", "/manager/html", "/_ignition", "/telescope", "config.php", "config.json",
    ".bak", ".sql", ".tar", ".tar.gz", ".tgz", "/backup.", "/dump.",
    "../", "..%2f", "%2e%2e", "/etc/passwd", "/etc/shadow", "win.ini",
    "eval(", "<script", "union+select", "union%20select", "/bin/sh", "/bin/bash",
]


def evaluate_security(sec: dict, cfg) -> "list[Signal]":
    """`sec` = Ausgabe von ESClient.security_window(). Liefert Security-Signale.

    Erwartetes Schema:
      {
        "total_requests": int,
        "suspicious": {"count": int, "paths": {path: count}, "ips": {ip: count}},
        "by_ip": {ip: {"total": int, "c4xx": int, "auth_fail": int, "distinct_paths": int}},
      }
    """
    signals: list[Signal] = []
    if not getattr(cfg, "security_check", True):
        return signals

    win = getattr(cfg, "window_hours", 6.0)

    # 1) Verdächtige Pfade (Scanner-/Exploit-Signaturen).
    susp = sec.get("suspicious") or {}
    susp_count = int(susp.get("count", 0))
    if susp_count >= cfg.security_min_suspicious:
        top_paths = "; ".join(list((susp.get("paths") or {}).keys())[:5]) or "—"
        top_ips = ", ".join(list((susp.get("ips") or {}).keys())[:5]) or "unbekannt"
        signals.append(Signal(
            "suspicious_requests", "high",
            f"{susp_count} verdächtige Scan-/Exploit-Aufrufe im {win:g}h-Fenster "
            f"(z.B. {top_paths}). Quell-IP(s): {top_ips}."))

    # 2)/3) Pro Quell-IP: Enumeration (viele 4xx über viele Pfade) und Auth-Brute-Force.
    by_ip = sec.get("by_ip") or {}
    for ip, st in sorted(by_ip.items(), key=lambda kv: kv[1].get("c4xx", 0), reverse=True):
        c4xx = int(st.get("c4xx", 0))
        paths = int(st.get("distinct_paths", 0))
        auth = int(st.get("auth_fail", 0))
        if c4xx >= cfg.security_scan_min_4xx and paths >= cfg.security_scan_min_paths:
            signals.append(Signal(
                "api_scan", "high",
                f"IP {ip}: {c4xx} 4xx-Antworten über {paths} verschiedene Pfade im "
                f"{win:g}h-Fenster — systematische Enumeration/Scan."))
        if auth >= cfg.security_auth_fail_threshold:
            signals.append(Signal(
                "auth_bruteforce", "high",
                f"IP {ip}: {auth} abgelehnte Auth-Antworten (401/403) im {win:g}h-Fenster "
                f"— möglicher Brute-Force/Credential-Stuffing."))

    return signals
