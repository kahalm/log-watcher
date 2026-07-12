"""Linux-System-Heuristik: überwacht die per Filebeat/journald eingelieferten
System-Logs (Host + VMs, Index-Pattern via ``LINUX_INDICES``, z.B. filebeat-*).

Deterministische Signale je Host:

- linux_ssh_bruteforce : viele fehlgeschlagene SSH-Logins („Failed password" /
                         „Invalid user") auf EINEM Host → Brute-Force. Wird wie
                         die Security-Signale IMMER alarmiert (LLM darf nicht
                         herabstufen).
- linux_oom            : der Kernel-OOM-Killer hat zugeschlagen — ein Prozess
                         wurde wegen Speichermangel abgeschossen.
- linux_disk_errors    : Block-/Dateisystem-Fehler (I/O error, EXT4-/XFS-
                         Korruption) — deutet auf sterbende Platte/Dateisystem.
- linux_unit_failures  : auffällig viele systemd-Unit-Fehlschläge („entered
                         failed state" / „Failed with result").
- linux_host_silent    : ein Host, der im Vorfenster geloggt hat, liefert im
                         aktuellen Fenster NICHTS mehr → Filebeat/VM/Host tot.

Die Message-Matches laufen als match_phrase über das Volltext-Feld ``message``
(journald parst Meldungen nicht in Felder); Schwellen sind konservativ und per
Config justierbar.
"""
from __future__ import annotations

from .rules import Signal

# Signal-Arten dieses Moduls.
LINUX_KINDS = {
    "linux_ssh_bruteforce", "linux_oom", "linux_disk_errors",
    "linux_unit_failures", "linux_host_silent",
}
# Wie SECURITY_KINDS: erzwingen einen Alarm, der LLM darf sie nicht wegbeurteilen.
FORCED_KINDS = {"linux_ssh_bruteforce"}

# match_phrase-Muster je Kategorie (case-insensitiv analysiert der Standard-Analyzer).
SSH_FAIL_PHRASES = ["Failed password", "Invalid user"]
OOM_PHRASES = ["Out of memory", "oom-kill", "oom_reaper"]
DISK_PHRASES = ["I/O error", "EXT4-fs error", "XFS", "Medium Error", "critical medium error"]
UNIT_FAIL_PHRASES = ["entered failed state", "Failed with result"]


def evaluate_linux(lin: dict, cfg) -> "list[Signal]":
    """`lin` = Ausgabe von ESClient.linux_window(). Liefert Linux-Signale.

    Erwartetes Schema:
      {
        "hosts": {host: {"total": int, "ssh_fail": int, "oom": int,
                          "disk": int, "unit_fail": int}},
        "baseline_hosts": {host: total_docs_im_vorfenster},
      }
    """
    signals: list[Signal] = []
    if not getattr(cfg, "linux_check", True):
        return signals

    win = getattr(cfg, "window_hours", 6.0)
    hosts = lin.get("hosts") or {}

    for host, st in sorted(hosts.items()):
        ssh = int(st.get("ssh_fail", 0))
        oom = int(st.get("oom", 0))
        disk = int(st.get("disk", 0))
        unit = int(st.get("unit_fail", 0))

        if ssh >= cfg.linux_ssh_fail_threshold:
            signals.append(Signal(
                "linux_ssh_bruteforce", "high",
                f"Host {host}: {ssh} fehlgeschlagene SSH-Logins im {win:g}h-Fenster "
                f"— möglicher Brute-Force."))
        if oom >= cfg.linux_oom_threshold:
            signals.append(Signal(
                "linux_oom", "high",
                f"Host {host}: {oom} OOM-Killer-Ereignis(se) im {win:g}h-Fenster "
                f"— Prozess(e) wegen Speichermangel abgeschossen."))
        if disk >= cfg.linux_disk_error_threshold:
            signals.append(Signal(
                "linux_disk_errors", "high",
                f"Host {host}: {disk} Disk-/Dateisystem-Fehlermeldung(en) im "
                f"{win:g}h-Fenster (I/O error / FS-Korruption) — Platte prüfen!"))
        if unit >= cfg.linux_unit_fail_threshold:
            signals.append(Signal(
                "linux_unit_failures", "medium",
                f"Host {host}: {unit} systemd-Unit-Fehlschläge im {win:g}h-Fenster."))

    # Verstummte Hosts: im Vorfenster aktiv, jetzt komplett still.
    if getattr(cfg, "linux_host_silent_check", True):
        baseline = lin.get("baseline_hosts") or {}
        min_docs = int(getattr(cfg, "linux_host_silent_min_baseline", 10))
        for host, base_count in sorted(baseline.items()):
            if base_count >= min_docs and int((hosts.get(host) or {}).get("total", 0)) == 0:
                signals.append(Signal(
                    "linux_host_silent", "high",
                    f"Host {host} liefert keine System-Logs mehr (Vorfenster: "
                    f"{base_count} Einträge, aktuelles {win:g}h-Fenster: 0) — "
                    f"Filebeat/VM/Host prüfen."))

    return signals
