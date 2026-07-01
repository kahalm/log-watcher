"""Push des laufenden Build an rookhubs Admin-CI (Feature: welches Image läuft)."""
import requests

from watcher import main


class _Resp:
    def __init__(self, status_code=204):
        self.status_code = status_code


def test_no_config_does_not_post(monkeypatch):
    calls = []
    monkeypatch.setattr(requests, "post", lambda *a, **k: calls.append((a, k)) or _Resp())
    for k in ("ROOKHUB_BUILD_REPORT_URL", "CI_BUILD_REPORT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    main._report_build_to_rookhub()
    assert calls == []   # ohne URL/Secret kein Request


def test_posts_payload_and_secret_header(monkeypatch):
    calls = []
    monkeypatch.setattr(requests, "post", lambda *a, **k: calls.append((a, k)) or _Resp(204))
    monkeypatch.setenv("ROOKHUB_BUILD_REPORT_URL", "http://api:8080/api/ci/build-report")
    monkeypatch.setenv("CI_BUILD_REPORT_SECRET", "s3cret")
    monkeypatch.setenv("GIT_SHA", "abc123")
    monkeypatch.setenv("GIT_REF", "v1.2.3")

    main._report_build_to_rookhub()

    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[0] == "http://api:8080/api/ci/build-report"
    assert kwargs["json"] == {"repo": "log-watcher", "sha": "abc123", "ref": "v1.2.3"}
    assert kwargs["headers"]["X-Build-Report-Key"] == "s3cret"


def test_never_raises_on_error(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network down")
    monkeypatch.setattr(requests, "post", boom)
    monkeypatch.setenv("ROOKHUB_BUILD_REPORT_URL", "http://api:8080/api/ci/build-report")
    monkeypatch.setenv("CI_BUILD_REPORT_SECRET", "s3cret")
    main._report_build_to_rookhub()   # darf NICHT werfen
