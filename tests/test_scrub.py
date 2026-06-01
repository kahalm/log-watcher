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
