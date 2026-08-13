from pathlib import Path
from types import SimpleNamespace

from apps.relay import control


def test_testmail_disables_delivery_status_notifications(monkeypatch):
    captured = {}

    def run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="queued as 9ABCD12345")

    monkeypatch.setattr(control.subprocess, "run", run)

    output = control.send_test_mail(
        "recipient@example.com", "sender@example.com", "Test", "Body"
    )

    assert captured["args"] == [
        "/usr/sbin/sendmail",
        "-v",
        "-N",
        "never",
        "-t",
        "-f",
        "sender@example.com",
    ]
    assert output == "queued as 9ABCD12345"


def test_mail_log_reads_persistent_data_file(tmp_path, monkeypatch):
    persistent = tmp_path / "maillog"
    persistent.write_text("postfix persistent entry\n", encoding="utf-8")
    legacy = tmp_path / "mail.log"
    legacy.write_text("legacy entry\n", encoding="utf-8")
    monkeypatch.setattr(control, "MAIL_LOG_PATH", persistent)
    monkeypatch.setattr(control, "LEGACY_MAIL_LOG_PATH", legacy)

    assert control.mail_log() == "postfix persistent entry\n"


def test_mail_log_falls_back_for_images_using_debian_syslog_path(tmp_path, monkeypatch):
    persistent = Path("/data/log/maillog")
    legacy = tmp_path / "mail.log"
    legacy.write_text("postfix compatibility entry\n", encoding="utf-8")
    monkeypatch.setattr(control, "DATA_DIR", Path("/data"))
    monkeypatch.setattr(control, "MAIL_LOG_PATH", persistent)
    monkeypatch.setattr(control, "LEGACY_MAIL_LOG_PATH", legacy)

    assert control.mail_log() == "postfix compatibility entry\n"


def test_delivery_evidence_correlates_sendmail_queue_id(monkeypatch):
    monkeypatch.setattr(control, "sh", lambda *_args, **_kwargs: "Mail queue is empty")
    monkeypatch.setattr(
        control,
        "mail_log",
        lambda *_args: "Aug 13 postfix/smtp[42]: 9ABCD12345: status=sent (250 accepted)\n",
    )

    evidence = control.delivery_evidence(
        "250 2.0.0 Ok: queued as 9ABCD12345", max_wait_seconds=1
    )

    assert evidence["queue_id"] == "9ABCD12345"
    assert evidence["state"] == "sent"
    assert evidence["in_queue"] is False
