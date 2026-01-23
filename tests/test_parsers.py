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


def test_apache_parser_common_format_without_referer_ua():
    parser = LogStatix.ApacheParser()
    line = (
        '127.0.0.1 - - [20/Jun/2024:14:04:16 +0700] '
        '"POST /api/key/activate?readonly=false HTTP/1.1" 404 303'
    )
    entry = parser.parse_line(line)

    assert entry is not None
    assert entry.ip == "127.0.0.1"
    assert entry.username == "-"
    assert entry.method == "POST"
    assert entry.url == "/api/key/activate?readonly=false"
    assert entry.status == "404"
    assert entry.referer is None
    assert entry.user_agent is None
    assert entry.time_request == "20/Jun/2024:14:04:16 +0700"


def test_apache_parser_escaped_quotes_in_request():
    parser = LogStatix.ApacheParser()
    line = (
        '127.0.0.1 - - [20/Jun/2024:14:05:00 +0700] '
        '"GET /catalog-portal/ui/oauth/verify?error=&deviceUdid=$%7b\\"'
        'freemarker.template.utility.Execute\\"%3fnew()(\\"cat+/etc/shells\\")%7d '
        'HTTP/1.1" 404 295 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"'
    )
    entry = parser.parse_line(line)

    assert entry is not None
    assert entry.method == "GET"
    assert entry.status == "404"
    assert entry.url.startswith("/catalog-portal/ui/oauth/verify?error=&deviceUdid=")