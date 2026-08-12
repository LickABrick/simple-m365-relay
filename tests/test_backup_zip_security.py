import io
import zipfile

import pytest


def _make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("meta.json", b"{}")
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_postfix_backup_rejects_too_many_entries():
    from postfix import backup as pb

    files = {f"junk/{i}.txt": b"x" for i in range(pb.MAX_ENTRIES + 10)}
    files["config/config.json"] = b"{}"
    blob = _make_zip(files)

    with pytest.raises(ValueError, match="too many entries"):
        pb.validate_and_extract_bundle(blob)


def test_postfix_backup_rejects_oversized_config_member():
    from postfix import backup as pb

    blob = _make_zip({"config/config.json": b"x" * (pb.MAX_CONFIG_BYTES + 1)})
    with pytest.raises(ValueError, match="too large"):
        pb.validate_and_extract_bundle(blob)


def test_postfix_backup_traversal_only_is_empty_bundle():
    from postfix import backup as pb

    blob = _make_zip({"../config/config.json": b"{}"})
    with pytest.raises(ValueError, match="empty"):
        pb.validate_and_extract_bundle(blob)


def test_postfix_backup_round_trip_uses_dovecot_users(tmp_path):
    from postfix import backup as pb

    (tmp_path / "config").mkdir()
    (tmp_path / "sasl").mkdir()
    (tmp_path / "config" / "config.json").write_text('{"hostname":"relay.local"}\n', encoding="utf-8")
    (tmp_path / "sasl" / "users").write_text("alice:{PLAIN}secret\n", encoding="utf-8")

    blob, meta = pb.export_bundle(tmp_path)
    parsed = pb.validate_and_extract_bundle(blob)

    assert meta["includes"]["smtp_auth_users"] is True
    assert parsed["users_bytes"] == b"alice:{PLAIN}secret\n"
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        assert "sasl/users" in archive.namelist()
        assert "sasl/sasldb2" not in archive.namelist()


def test_postfix_backup_rejects_legacy_sasldb_import(tmp_path):
    from postfix import backup as pb

    blob = _make_zip({"sasl/sasldb2": b"legacy-db"})
    with pytest.raises(ValueError, match="Legacy sasldb2"):
        pb.import_bundle(tmp_path, blob)


def test_import_config_rejects_control_characters():
    from app.config import validate_cfg_obj

    with pytest.raises(ValueError, match="invalid characters"):
        validate_cfg_obj({"hostname": "relay.local\nmain.cf injection"})


def test_import_config_rejects_invalid_nested_shapes():
    from app.config import validate_cfg_obj

    with pytest.raises(ValueError, match="address lists"):
        validate_cfg_obj({"allowed_from": {"alice": "not-a-list"}})
