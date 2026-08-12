from pathlib import Path

from apps.relay import control


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
