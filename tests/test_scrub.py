from watcher import scrub


def test_redacts_email_ip_token():
    s = scrub.scrub("login user@example.com from 10.24.12.12 token=ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
    assert "user@example.com" not in s and "<email>" in s
    assert "10.24.12.12" not in s and "<ip>" in s
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
    s = scrub.scrub("client 2001:0db8:85a3:0000:0000:8a2e:0370:7334 blocked")
    assert "2001" not in s and "<ip>" in s
    assert "<ip>" in scrub.scrub("from ::1")
    assert "<ip>" in scrub.scrub("link-local fe80::1%eth0")
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
