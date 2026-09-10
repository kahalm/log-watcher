from watcher import scrub


def test_redacts_email_ip_token():
    # 84.114.12.12 ist oeffentlich — private Adressen bleiben seit v0.22.0 bewusst lesbar.
    s = scrub.scrub("login user@example.com from 84.114.12.12 token=ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
    assert "user@example.com" not in s and "<email>" in s
    assert "84.114.12.12" not in s and "<ip>" in s
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" not in s and "<token>" in s


def test_redacts_bearer_and_jwt():
    s = scrub.scrub("Authorization: Bearer abc.def-ghi123")
    assert "bearer <token>" in s.lower()
    j = scrub.scrub("token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 rest")
    assert "<jwt>" in j


def test_redacts_url_credentials():
    s = scrub.scrub("mysql://admin:s3cretPass@db:3306/x")
    assert "s3cretPass" not in s


def test_scrub_messages_sums_on_collision():
    msgs = {"user a@b.com failed": 3, "user c@d.com failed": 2}
    out = scrub.scrub_messages(msgs)
    # beide kollabieren zu "user <email> failed"
    assert out == {"user <email> failed": 5}


def test_scrub_keeps_plain_text():
    assert scrub.scrub("database connection refused") == "database connection refused"


def test_redacts_ipv6():
    # 2606:4700::/32 ist oeffentlich; ::1/fe80:: sind intern und bleiben seit v0.22.0 lesbar
    # (2001:db8::-Doku-Adressen zaehlt ipaddress uebrigens ebenfalls als privat).
    s = scrub.scrub("client 2606:4700:4700:0000:0000:0000:0000:1111 blocked")
    assert "2606" not in s and "<ip>" in s
    assert "<ip>" in scrub.scrub("peer 2a02:8109::42:1 timed out")


def test_ipv6_pattern_keeps_timestamps_and_macs():
    # Uhrzeiten/MACs dürfen nicht als IPv6 durchgehen — sonst wird jede Logzeile unlesbar.
    assert scrub.scrub("2026-06-01T12:34:56.000Z ok") == "2026-06-01T12:34:56.000Z ok"
    assert scrub.scrub("mac aa:bb:cc:dd:ee:ff") == "mac aa:bb:cc:dd:ee:ff"


def test_scrub_signals_redacts_details():
    class _S:
        kind = "auth_bruteforce"
        severity_hint = "high"
        detail = "IP 45.9.1.2: 30 abgelehnte Auth-Antworten"

    sigs = scrub.scrub_signals([_S()])
    assert "45.9.1.2" not in sigs[0].detail and "<ip>" in sigs[0].detail


# ── Private Adressen bleiben lesbar (Fall 09.09.2026: "<ip>:<ip>" verschleierte den
#    eigenen Docker-Gateway und machte einen hausgemachten Sweep zum "externen Scanner") ──

def test_private_ips_bleiben_lesbar():
    from watcher.scrub import scrub
    s = scrub("Zugriff von 10.24.13.6 und 192.168.1.2 und 172.28.0.1 auf Server")
    assert "10.24.13.6" in s and "192.168.1.2" in s and "172.28.0.1" in s
    assert "<ip>" not in s


def test_public_ips_werden_weiter_redigiert():
    from watcher.scrub import scrub
    assert scrub("Scan von 45.155.205.233 erkannt") == "Scan von <ip> erkannt"
    assert scrub("via 2a00:1450:4001:80b::200e") == "via <ip>"


def test_ipv4_mapped_privat_bleibt_am_stueck():
    from watcher.scrub import scrub
    s = scrub("IP ::ffff:172.28.0.1: 744 4xx-Antworten")
    assert "::ffff:172.28.0.1" in s and "<ip>" not in s


def test_ipv4_mapped_public_wird_redigiert():
    from watcher.scrub import scrub
    s = scrub("IP ::ffff:8.8.8.8: 12 Requests")
    assert "8.8.8.8" not in s


def test_loopback_und_linklocal_bleiben():
    from watcher.scrub import scrub
    s = scrub("von 127.0.0.1 und ::1 und fe80::d65d:64ff:fed7:63b7 kam nichts")
    assert "127.0.0.1" in s and "::1" in s and "fe80::d65d:64ff:fed7:63b7" in s


def test_unparsebares_wird_redigiert():
    from watcher.scrub import scrub
    # 999.… matcht die IPv4-Regex, ist aber keine gueltige Adresse -> sicherer Default: weg.
    assert scrub("kaputt 999.1.1.1 Ende") == "kaputt <ip> Ende"
