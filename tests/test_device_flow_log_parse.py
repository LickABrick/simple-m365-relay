import importlib
import os
from pathlib import Path


def _load_main(tmp_path: Path):
    os.environ["DATA_DIR"] = str(tmp_path)
    import app.main as main

    importlib.reload(main)
    return main


def test_parse_device_flow_log_extracts_url_and_plain_code(tmp_path):
    main = _load_main(tmp_path)

    log = (
        "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and "
        "enter the code H1TY9Q3YK to authenticate.\n"
        "[exit 0]\n"
    )

    j = main._parse_device_flow_log(log)
    assert j["url"] == "https://microsoft.com/devicelogin"
    assert j["code"] == "H1TY9Q3YK"
    assert j["done"] is True
    assert j["ok"] is True


def test_parse_device_flow_log_normalizes_lowercase_code(tmp_path):
    main = _load_main(tmp_path)

    log = "Open https://microsoft.com/devicelogin and use code ab12cd34ef.\n"

    j = main._parse_device_flow_log(log)
    assert j["url"] == "https://microsoft.com/devicelogin"
    assert j["code"] == "AB12CD34EF"


def test_parse_device_flow_log_extracts_hyphenated_code(tmp_path):
    main = _load_main(tmp_path)

    log = "Open microsoft.com/devicelogin and enter the code abcd-efgh.\n"

    j = main._parse_device_flow_log(log)
    assert j["url"] == "https://microsoft.com/devicelogin"
    assert j["code"] == "ABCD-EFGH"
