from watcher.fingerprint import fingerprint


def test_numbers_normalized():
    assert fingerprint("timeout after 30s") == fingerprint("timeout after 45s")


def test_guid_normalized():
    a = "user 550e8400-e29b-41d4-a716-446655440000 failed"
    b = "user 11111111-2222-3333-4444-555555555555 failed"
    assert fingerprint(a) == fingerprint(b)


def test_quoted_normalized():
    assert fingerprint("file 'a.txt' not found") == fingerprint('file "b.log" not found')


def test_distinct_messages_kept_distinct():
    assert fingerprint("database down") != fingerprint("cache down")
