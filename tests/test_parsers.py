from importlib import util
from pathlib import Path

# Load from file path to avoid import path issues in CI.
MODULE_PATH = Path(__file__).resolve().parents[1] / "LogStatix.py"
spec = util.spec_from_file_location("LogStatix", MODULE_PATH)
assert spec and spec.loader
LogStatix = util.module_from_spec(spec)
spec.loader.exec_module(LogStatix)


def test_iis_parser_parses_fields():
    parser = LogStatix.IISParser()
    header = (
        "#Fields: date time cs-method cs-uri-stem cs-uri-query sc-status "
        "c-ip cs(User-Agent) cs(Referer) cs-username"
    )
    assert parser.parse_line(header) is None

    line = (
        "2024-01-02 03:04:05 GET /index.php id=1 200 192.0.2.1 "
        "Mozilla/5.0 http://example.com/ alice"
    )
    entry = parser.parse_line(line)

    assert entry is not None
    assert entry.ip == "192.0.2.1"
    assert entry.url == "/index.php?id=1"
    assert entry.status == "200"
    assert entry.user_agent == "Mozilla/5.0"
    assert entry.referer == "http://example.com/"
    assert entry.username == "alice"
    assert entry.method == "GET"
    assert entry.filename == "/index.php"
    assert entry.param == "id=1"
    assert entry.time_request == "2024-01-02 03:04:05"


def test_apache_parser_combined_format():
    parser = LogStatix.ApacheParser()
    line = (
        '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] '
        '"GET /apache_pb.gif HTTP/1.0" 200 2326 '
        '"http://example.com/start" "Mozilla/5.0"'
    )
    entry = parser.parse_line(line)

    assert entry is not None
    assert entry.ip == "127.0.0.1"
    assert entry.username == "frank"
    assert entry.method == "GET"
    assert entry.url == "/apache_pb.gif"
    assert entry.status == "200"
    assert entry.referer == "http://example.com/start"
    assert entry.user_agent == "Mozilla/5.0"
    assert entry.time_request == "10/Oct/2000:13:55:36 -0700"


def test_apache_parser_custom_format_with_tz():
    parser = LogStatix.ApacheParser()
    line = (
        "192.0.2.1 - alice [10/Oct/2000:13:55:36] +0000 "
        "GET GET /index.html HTTP/1.1 example.com 200 123 "
        '"-" "Mozilla/5.0" 192.0.2.1'
    )
    entry = parser.parse_line(line)

    assert entry is not None
    assert entry.ip == "192.0.2.1"
    assert entry.username == "alice"
    assert entry.method == "GET"
    assert entry.url == "/index.html"
    assert entry.status == "200"
    assert entry.referer == "-"
    assert entry.user_agent == "Mozilla/5.0"
    assert entry.time_request == "10/Oct/2000:13:55:36 +0000"
