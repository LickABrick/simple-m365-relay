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
