"""_notify: der eine Versandweg für Mail + Discord, mit DRY_RUN und Logging (Fund S5-012)."""
import logging
from unittest.mock import patch

from watcher.config import Config
from watcher.main import _notify


def _cfg(smtp=True, discord=True, dry_run=False):
    cfg = Config()
    cfg.name = "t"
    cfg.dry_run = dry_run
    cfg.smtp_host = "smtp.example" if smtp else None
    cfg.smtp_from = "w@example"
    cfg.smtp_to = ["ops@example"]
    cfg.discord_webhook_url = "https://discord.example/webhook" if discord else None
    return cfg


def test_reports_the_channels_that_delivered():
    with patch("watcher.main.notifier.send_email") as mail, \
         patch("watcher.main.discord_notify.post_text") as post:
        sent = _notify(_cfg(), "Digest", "hallo", mail=("Betreff", "Text", "<p>Text</p>"))
    assert sent == {"email", "discord"}
    mail.assert_called_once()
    assert mail.call_args.args[1:] == ("Betreff", "Text", "<p>Text</p>")
    post.assert_called_once_with("https://discord.example/webhook", "hallo")


def test_one_failed_channel_still_counts_the_other(caplog):
    with patch("watcher.main.notifier.send_email", side_effect=OSError("SMTP weg")), \
         patch("watcher.main.discord_notify.post_text"), \
         caplog.at_level(logging.INFO, logger="log-watcher"):
        sent = _notify(_cfg(), "Digest", "hallo", mail=("B", "T", None))
    assert sent == {"discord"}
    assert any(r.levelno == logging.ERROR and "E-Mail fehlgeschlagen" in r.getMessage()
               for r in caplog.records)


def test_all_channels_failing_is_empty_and_never_raises():
    with patch("watcher.main.notifier.send_email", side_effect=OSError("SMTP weg")), \
         patch("watcher.main.discord_notify.post_text", side_effect=OSError("HTTP 502")):
        assert not _notify(_cfg(), "All-is-well-Meldung", "hallo", mail=("B", "T", None))


def test_payload_builder_error_counts_as_channel_failure():
    def boom():
        raise KeyError("total")

    with patch("watcher.main.discord_notify.post") as post:
        assert _notify(_cfg(smtp=False), "Alert", payload=boom) == set()
    post.assert_not_called()


def test_payload_goes_through_post_not_post_text():
    with patch("watcher.main.discord_notify.post") as post, \
         patch("watcher.main.discord_notify.post_text") as post_text:
        assert _notify(_cfg(smtp=False), "Alert", payload=lambda: {"embeds": []}) == {"discord"}
    post.assert_called_once_with("https://discord.example/webhook", {"embeds": []})
    post_text.assert_not_called()


def test_discord_only_messages_send_no_mail():
    with patch("watcher.main.notifier.send_email") as mail, \
         patch("watcher.main.discord_notify.post_text"):
        assert _notify(_cfg(), "LLM-Entwarnung", "✅") == {"discord"}
    mail.assert_not_called()


def test_dry_run_sends_nothing_and_counts_as_delivered(caplog):
    with patch("watcher.main.notifier.send_email") as mail, \
         patch("watcher.main.discord_notify.post_text") as post, \
         caplog.at_level(logging.INFO, logger="log-watcher"):
        sent = _notify(_cfg(dry_run=True), "Alert", "x", mail=("Betreff", "Text", None),
                       dry_level=logging.WARNING)
    assert sent == {"dry_run"}
    mail.assert_not_called()
    post.assert_not_called()
    rec = [r for r in caplog.records if "DRY_RUN" in r.getMessage()]
    assert rec and rec[0].levelno == logging.WARNING and "Betreff" in rec[0].getMessage()
