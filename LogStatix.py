import abc
import argparse
import base64
import csv
import html
import json
import math
import os
import re
import time
import urllib.parse
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional
from zipfile import ZipFile

import pandas as pd


# ==========================================
# CONSTANTS & CONFIGURATION
# ==========================================
class AppConfig:
    BATCH_SIZE = 1000
    MAX_EXCEL_ROWS = 1000000
    ENCODING_READ = "cp437"
    ENCODING_WRITE = "utf-8"
    FORMAT_DATETIME = "%d%m%Y_%H%M%S%f"
    PATH_PATTERN = "patterns.json"
    REGEX_NORMAl_REQ = r"^[a-zA-Z0-9;/&.,?+=_-]+$"
    ENTROPY = 5
    RATIO_SPEC_CHAR = 0.2
    REGEX_EXTENSION = re.compile(
        r"[!-~]+\.(php|xml|java|aspx|asp|py|rb|js|jsp|jspx|sh|jar|cgi|ashx|ascx|asmx|eas)",
        re.IGNORECASE,
    )
    STATIC_EXTS = (
        ".css",
        ".js",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".ico",
        ".svg",
        ".html",
        ".htm",
    )


class HttpDefinitions:
    # success code startwith 2 or 3 and len 3
    @staticmethod
    def classify_success_or_fail(status: str):
        return (
            True
            if (status.startswith("2") or status.startswith("3")) and len(status) == 3
            else False
        )

    # check extension of web file
    @staticmethod
    def is_valid_web_exts(filename: str):
        return AppConfig.REGEX_EXTENSION.search(filename)

    # webshell maybe fake by static file
    @staticmethod
    def _is_static_file(path: str) -> bool:
        return path.lower().endswith(AppConfig.STATIC_EXTS)


# ==========================================
# DATA MODELS
# ==========================================
@dataclass
class UserAgentStat:
    count: int = 0


@dataclass
class IPStat:
    fail: int = 0
    success: int = 0
    total: int = 0
    first_time: str = str()
    last_time: str = str()


@dataclass
class FileRequestStat:
    time_request: str
    post: int
    filename: str
    count: int
    extension: str
    param: str
    filename_request: str
    count_success: int = 0
    count_fail: int = 0


@dataclass
class LogEntry:
    ip: str
    referer: str
    url: str
    status: str
    user_agent: str
    time_request: str
    username: str
    method: str
    filename: str = str()
    param: str = str()
    raw_line: str = str()


# ==========================================
# UTILITIES
# ==========================================
class FileUtils:
    @staticmethod
    def unzip_file(path_archive: str) -> str:
        with ZipFile(path_archive, "r") as zf:
            folder_name = os.path.dirname(path_archive)
            curr_time = datetime.now().strftime(AppConfig.FORMAT_DATETIME)
            path_extract = os.path.join(folder_name, "log_" + curr_time)
            zf.extractall(path_extract)
            return path_extract

    @staticmethod
    def write_csv_rows(path_log: str, rows: list):
        os.makedirs(os.path.dirname(path_log), exist_ok=True)
        with open(path_log, "a", encoding=AppConfig.ENCODING_WRITE, newline="") as f:
            writer = csv.writer(f)
            writer.writerows(rows)


# ==========================================
# Decode obfuscate request via multi layer
# refer: https://github.com/nemesida-waf/waf-bypass
# ==========================================
class DecoderStrategy(abc.ABC):
    @abc.abstractmethod
    def decode(self, text: str) -> str:
        pass


class UrlDecoder(DecoderStrategy):
    def decode(self, text: str) -> str:
        # Decode encode-URL (%20, %25, +)
        return urllib.parse.unquote_plus(text)


class HtmlEntityDecoder(DecoderStrategy):
    def decode(self, text: str) -> str:
        # Decode &amp;, &#xXX;
        return html.unescape(text)


class IISUnicodeDecoder(DecoderStrategy):
    def decode(self, text: str) -> str:
        # Decode IIS %uXXXX -> char
        return re.sub(
            r"%u([0-9a-fA-F]{4})",
            lambda x: chr(int(x.group(1), 16)),
            text,
            flags=re.IGNORECASE,
        )


class EscapeSequenceDecoder(DecoderStrategy):
    def decode(self, text: str) -> str:
        # 1. Hex escape: \x41 -> A
        text = re.sub(
            r"\\x([0-9a-fA-F]{2})",
            lambda x: chr(int(x.group(1), 16)),
            text,
            flags=re.IGNORECASE,
        )
        # 2. Unicode escape: \u0041 -> A
        text = re.sub(
            r"\\u([0-9a-fA-F]{4})",
            lambda x: chr(int(x.group(1), 16)),
            text,
            flags=re.IGNORECASE,
        )
        # 3. Octal escape: \101 -> A
        text = re.sub(r"\\([0-7]{1,3})", lambda x: chr(int(x.group(1), 8)), text)
        return text


class SqlCommentRemover(DecoderStrategy):
    def decode(self, text: str) -> str:
        # remove comment: SEL/**/ECT -> SELECT
        return re.sub(r"/\*.*?\*/", "", text)


class WhitespaceNormalizer(DecoderStrategy):
    def decode(self, text: str) -> str:
        # remove space: %09, %0a, %0b, %0c, %0d...
        return re.sub(r"[\t\n\r\f\v\xa0]+", " ", text)


class Base64SmartDecoder(DecoderStrategy):
    def decode(self, text: str) -> str:
        # only decode if length greater than 20 to prevent false
        # if false-positive not match, please up length base64 regex
        pattern = r"([A-Za-z0-9+/=_ -]{20,})"

        def b64_replace(match):
            original_str = match.group(0)
            try:
                temp_str = original_str.strip()
                # Fix padding
                padding = len(temp_str) % 4
                if padding:
                    temp_str += "=" * (4 - padding)
                # Fix URL-safe base64
                temp_str = temp_str.replace("-", "+").replace("_", "/")

                decoded_bytes = base64.b64decode(temp_str, validate=True)

                printable_chars = set(bytes(range(32, 127)) + b"\r\n\t")
                if all(b in printable_chars for b in decoded_bytes):
                    return decoded_bytes.decode("utf-8", errors="ignore")
            except Exception:
                pass
            return original_str

        return re.sub(pattern, b64_replace, text)


# ==========================================
# Find attack request via pattern regex
# ==========================================
class ScannerVulnerability:
    def __init__(self, pattern_file=AppConfig.PATH_PATTERN):
        self.compiled_patterns = {}
        self.false_patterns = []
        self.pattern_file = pattern_file

        self.break_line = re.compile(r"[\r\n]+", re.IGNORECASE)
        self.non_printable = re.compile(
            r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", re.IGNORECASE
        )

        self.strategies: list[DecoderStrategy] = [
            UrlDecoder(),
            Base64SmartDecoder(),
            IISUnicodeDecoder(),
            EscapeSequenceDecoder(),
            HtmlEntityDecoder(),
            SqlCommentRemover(),
            WhitespaceNormalizer(),
        ]

        self.load_patterns()

    # db in patters.txt
    def load_patterns(self):
        if not os.path.exists(self.pattern_file):
            print(f"Warning: Pattern file {self.pattern_file} not found!")
            return

        with open(self.pattern_file, "r", encoding=AppConfig.ENCODING_READ) as f:
            data = json.load(f)

        for vuln_type, regex_list in data.items():
            compiled_list = [re.compile(p, re.IGNORECASE) for p in regex_list]
            if vuln_type == "false-positive":
                self.false_patterns = compiled_list
            else:
                self.compiled_patterns[vuln_type] = compiled_list

        print(f"[+] Loaded {len(self.compiled_patterns)} vulnerability categories.")

    def decode_url(self, line: str) -> Optional[str]:
        if not line:
            return None

        current_text = line
        max_iterations = len(self.strategies) * 3

        for _ in range(max_iterations):
            previous_text = current_text

            for strategy in self.strategies:
                decoded = str()
                # compare before and after each strategy to save time
                while True:
                    decoded = strategy.decode(current_text)
                    if decoded != current_text:
                        current_text = decoded
                    else:
                        break

            # clean unwanted character
            current_text = self.break_line.sub("", current_text)
            current_text = self.non_printable.sub("", current_text)
            current_text = current_text.replace("\x00", " ")

            # loop until before and after each loop are same than break
            if current_text == previous_text:
                break

        return current_text.encode("ascii", errors="ignore").decode("ascii").strip().lower()

    # exclude false positive in db
    def detect_false_positive(self, line) -> bool:
        return any(p.search(line) for p in self.false_patterns)

    # if payload is obfuscated, entropy maybe high
    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy

    def _check_webshell_suspect(self, entry: LogEntry) -> bool:
        if not entry.url:
            return False

        parsed = urllib.parse.urlparse(entry.url)
        path = parsed.path
        query = parsed.query
        method = entry.method.lower() if entry.method else ""

        # POST static file, fake image webshell
        if method == "post" and HttpDefinitions._is_static_file(path):
            return True

        # GET staic file include params
        if HttpDefinitions._is_static_file(path) and (query or method == "get"):
            return True

        # analyze params of GET, entropy and special characters
        if query:
            # if entropy greater than threshold, it maybe fuzzing or obfuscation
            entropy = self._calculate_entropy(query)
            if entropy > AppConfig.ENTROPY:
                return True

            # check ratio special characters (non printable characters) if greater than threshold
            non_alnum_count = sum(1 for c in query if not c.isalnum())
            if (
                len(query) > 0
                and (non_alnum_count / len(query)) > AppConfig.RATIO_SPEC_CHAR
            ):
                return True

        return False

    def dispatcher(self, line: str, entry: LogEntry) -> str:
        type_attack = ""
        for vuln_type, patterns in self.compiled_patterns.items():
            if any(p.search(line) for p in patterns):
                type_attack = vuln_type
                break
        if type_attack != "":
            return type_attack
        else:
            return "webshell|fuzzing" if self._check_webshell_suspect(entry) else ""


# ==========================================
# LOG PARSERS
# ==========================================
class LogParser:
    # parse each column to get value
    def parse_line(self, line: str) -> Optional[LogEntry]:
        raise NotImplementedError


class IISParser(LogParser):
    def __init__(self):
        self.idx = {}

    def parse_line(self, line: str) -> Optional[LogEntry]:
        if line.startswith("#Fields: "):
            cols = line[9:].strip().split()
            self.idx = {name: i for i, name in enumerate(cols)}
            return None
        elif line.startswith("#") or not self.idx:
            return None

        parts = line.split()

        def get(name):
            return parts[self.idx[name]] if name in self.idx else "-"

        url_stem = get("cs-uri-stem")
        url_query = get("cs-uri-query")
        url = url_stem + ("?" + url_query if url_query != "-" else "")
        ts = get("date") + " " + get("time")

        return LogEntry(
            ip=get("c-ip"),
            referer=get("cs(Referer)"),
            url=url,
            status=get("sc-status"),
            user_agent=get("cs(User-Agent)"),
            time_request=ts,
            username=get("cs-username"),
            method=get("cs-method"),
            filename=url_stem,
            param=url_query,
            raw_line=line,
        )


class ApacheParser(LogParser):
    def __init__(self):
        self.default_format = (
            '%h %l %u %t %z %m %r %v %>s %b "%{Referer}i" "%{User-Agent}i" %a'
        )
        self._pattern_custom = re.compile(
            r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
            r'\[(?P<time>[^\]]+)\]\s+(?P<tz>\S+)\s+(?P<method>\S+)\s+'
            r'(?P<request>.+?)\s+(?P<vhost>\S+)\s+(?P<status>\S+)\s+(?P<size>\S+)\s+'
            r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"\s+(?P<client_ip>\S+)\s*$'
        )
        self._pattern_custom_no_tz = re.compile(
            r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
            r'\[(?P<time>[^\]]+)\]\s+(?P<method>\S+)\s+'
            r'(?P<request>.+?)\s+(?P<vhost>\S+)\s+(?P<status>\S+)\s+(?P<size>\S+)\s+'
            r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"\s+(?P<client_ip>\S+)\s*$'
        )
        self._pattern_combined = re.compile(
            r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
            r'\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\S+)\s+'
            r'(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"\s*$'
        )

    @staticmethod
    def _parse_request(request: str):
        if not request:
            return None, None
        request = request.strip('"')
        parts = request.split()
        if len(parts) >= 2:
            return parts[0], parts[1]
        return None, request

    @staticmethod
    def _tokenize_line(line: str):
        return re.findall(r'"[^"]*"|\[[^\]]*\]|\S+', line)

    def parse_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None

        for pattern in (
            self._pattern_custom,
            self._pattern_custom_no_tz,
            self._pattern_combined,
        ):
            match = pattern.match(line)
            if not match:
                continue
            data = match.groupdict()
            time_request = data.get("time")
            tz = data.get("tz")
            if time_request and tz:
                time_request = f"{time_request} {tz}"
            request = data.get("request")
            method_from_request, uri = self._parse_request(request)
            method = data.get("method") or method_from_request
            if not uri and request:
                uri = request.strip('"')

            return LogEntry(
                ip=data.get("ip"),
                referer=data.get("referer"),
                url=uri,
                status=data.get("status"),
                user_agent=data.get("ua"),
                time_request=time_request,
                username=data.get("user"),
                method=method,
                raw_line=line,
            )

        parts = self._tokenize_line(line)
        ip = referer = uri = status = user_agent = time_request = username = method = (
            None
        )
        fields = self.default_format.split()
        request_line = None
        i = 0
        j = 0
        while i < len(fields) and j < len(parts):
            f = fields[i]
            token = parts[j]
            if f == "%h":
                ip = token
            elif f == "%r":
                request_line = token
                if (
                    not token.startswith('"')
                    and j + 2 < len(parts)
                    and parts[j + 2].upper().startswith("HTTP/")
                ):
                    request_line = " ".join(parts[j : j + 3])
                    j += 2
                elif (
                    not token.startswith('"')
                    and j + 1 < len(parts)
                    and parts[j + 1].startswith("/")
                ):
                    request_line = " ".join(parts[j : j + 2])
                    j += 1
                method_from_request, uri_candidate = self._parse_request(request_line)
                if not method and method_from_request:
                    method = method_from_request
                if uri_candidate:
                    uri = uri_candidate
            elif f == '"%{Referer}i"':
                referer = token.strip('"')
            elif f == "%>s":
                status = token
            elif f == "%t":
                time_request = token.strip("[]")
            elif f == "%z":
                if time_request:
                    time_request = f"{time_request} {token}"
            elif f == "%u":
                username = token.strip()
            elif f == "%m":
                method = token.strip()
            elif f == '"%{User-Agent}i"':
                user_agent = token.strip('"')
            i += 1
            j += 1

        return LogEntry(
            ip=ip,
            referer=referer,
            url=uri,
            status=status,
            user_agent=user_agent,
            time_request=time_request,
            username=username,
            method=method,
            raw_line=line,
        )


# ==========================================
# REPORT WRITER
# ==========================================
class ReportWriter:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.result_dir = os.path.join(output_dir, "result")
        os.makedirs(self.result_dir, exist_ok=True)

        self.p_attack = os.path.join(self.result_dir, "attack_request.csv")
        self.p_no_ua = os.path.join(self.result_dir, "no_user_agent.csv")
        self.p_ua = os.path.join(self.result_dir, "user_agent_official.csv")
        self.p_ua_unofficial = os.path.join(
            self.result_dir, "user_agent_non_official.csv"
        )
        self.p_ip = os.path.join(self.result_dir, "statistic_ip.csv")
        self.p_file = os.path.join(self.result_dir, "file_request.csv")
        self.p_file_count = os.path.join(self.result_dir, "file_request_count.csv")
        self.p_user = os.path.join(self.result_dir, "username.csv")

        self.buf_attack = deque()
        self.buf_no_ua = deque()

        FileUtils.write_csv_rows(
            self.p_attack,
            [["Status", "Success", "IP", "Url", "Datetime", "Type", "UserAgent"]],
        )
        FileUtils.write_csv_rows(self.p_no_ua, [["RawLogLine"]])

    def write_attack(self, row: list):
        self.buf_attack.append(row)
        if len(self.buf_attack) >= AppConfig.BATCH_SIZE:
            FileUtils.write_csv_rows(self.p_attack, self.buf_attack)
            self.buf_attack.clear()

    def write_no_ua(self, line: str):
        self.buf_no_ua.append([line.strip()])
        if len(self.buf_no_ua) >= AppConfig.BATCH_SIZE:
            FileUtils.write_csv_rows(self.p_no_ua, self.buf_no_ua)
            self.buf_no_ua.clear()

    def flush_buffers(self):
        if self.buf_attack:
            FileUtils.write_csv_rows(self.p_attack, self.buf_attack)
        if self.buf_no_ua:
            FileUtils.write_csv_rows(self.p_no_ua, self.buf_no_ua)
        self.buf_attack.clear()
        self.buf_no_ua.clear()

    def export_dictionaries(
        self, ip_stats, file_reqs, usernames, ua_stats, file_counts
    ):
        print("[+] Exporting CSVs...")
        # 1. User Agents
        ua_off, ua_unoff = [], []
        FileUtils.write_csv_rows(self.p_ua, [["UserAgent", "Count"]])
        FileUtils.write_csv_rows(self.p_ua_unofficial, [["UserAgent", "Count"]])
        for ua_str, stat in ua_stats.items():
            row = [ua_str, stat.count]
            # refer: https://gist.github.com/pzb/b4b6f57144aea7827ae4
            if ua_str and ua_str.startswith("Mozilla"):
                ua_off.append(row)
            else:
                ua_unoff.append(row)
            if len(ua_off) >= AppConfig.BATCH_SIZE:
                FileUtils.write_csv_rows(self.p_ua, ua_off)
                ua_off.clear()
            if len(ua_unoff) >= AppConfig.BATCH_SIZE:
                FileUtils.write_csv_rows(self.p_ua_unofficial, ua_unoff)
                ua_unoff.clear()
        if ua_off:
            FileUtils.write_csv_rows(self.p_ua, ua_off)
        if ua_unoff:
            FileUtils.write_csv_rows(self.p_ua_unofficial, ua_unoff)

        # 2. IP
        ip_buf = []
        FileUtils.write_csv_rows(
            self.p_ip, [["IP", "Fail", "Success", "Total", "First", "Last"]]
        )
        for ip, stat in ip_stats.items():
            ip_buf.append(
                [
                    ip,
                    stat.fail,
                    stat.success,
                    stat.total,
                    stat.first_time,
                    stat.last_time,
                ]
            )
            if len(ip_buf) >= AppConfig.BATCH_SIZE:
                FileUtils.write_csv_rows(self.p_ip, ip_buf)
                ip_buf.clear()
        if ip_buf:
            FileUtils.write_csv_rows(self.p_ip, ip_buf)

        # 3. File Requests
        fr_buf = []
        FileUtils.write_csv_rows(
            self.p_file,
            [
                [
                    "time",
                    "post",
                    "filename",
                    "count",
                    "success",
                    "fail",
                    "extension",
                    "param",
                    "file_request",
                    "url",
                ]
            ],
        )
        for url, stat in file_reqs.items():
            fr_buf.append(
                [
                    stat.time_request,
                    stat.post,
                    stat.filename,
                    stat.count,
                    stat.count_success,
                    stat.count_fail,
                    stat.extension,
                    stat.param,
                    stat.filename_request,
                    url,
                ]
            )
            if len(fr_buf) >= AppConfig.BATCH_SIZE:
                FileUtils.write_csv_rows(self.p_file, fr_buf)
                fr_buf.clear()
        if fr_buf:
            FileUtils.write_csv_rows(self.p_file, fr_buf)

        # 4. File Counts
        FileUtils.write_csv_rows(self.p_file_count, [["filename", "count"]])
        fc_buf = [[f, c] for f, c in file_counts.items()]
        FileUtils.write_csv_rows(self.p_file_count, fc_buf)

        # 5. Usernames
        FileUtils.write_csv_rows(self.p_user, [["username", "count"]])
        FileUtils.write_csv_rows(self.p_user, [[u, c] for u, c in usernames.items()])

    def convert_to_excel(self):
        csv_files = [
            os.path.join(self.result_dir, f)
            for f in os.listdir(self.result_dir)
            if f.endswith(".csv")
        ]
        print(f"[+] Converting {len(csv_files)} CSV files to Excel...")
        path_xlsx = os.path.join(self.result_dir, "report.xlsx")

        # split into multiple sheet if row greater 1M
        with pd.ExcelWriter(path_xlsx, engine="xlsxwriter") as writer:
            for csv_path in csv_files:
                try:
                    df = pd.read_csv(csv_path, encoding=AppConfig.ENCODING_READ, on_bad_lines="skip", low_memory=False)
                    base_name = os.path.splitext(os.path.basename(csv_path))[0]
                    rows = len(df)
                    if rows > AppConfig.MAX_EXCEL_ROWS:
                        # jump 1M each loop
                        for i in range(0, rows, AppConfig.MAX_EXCEL_ROWS):
                            chunk = df.iloc[i : i + AppConfig.MAX_EXCEL_ROWS]
                            suffix = f"_p{i // AppConfig.MAX_EXCEL_ROWS + 1}"
                            sheet_name = base_name[: (31 - len(suffix))] + suffix
                            chunk.to_excel(writer, sheet_name=sheet_name, index=False)
                    else:
                        df.to_excel(writer, sheet_name=base_name[:31], index=False)
                except Exception as e:
                    print(f"Error converting {csv_path}: {e}")
        for f in csv_files:
            os.remove(f)


# ==========================================
# CORE LOGIC PROCESSOR
# ==========================================
class LogAnalyzer:
    def __init__(
        self, parser: LogParser, scanner: ScannerVulnerability, writer: ReportWriter
    ):
        self.parser = parser
        self.scanner = scanner
        self.writer = writer

        self.stats_ip: Dict[str, IPStat] = {}
        self.stats_ua: Dict[str, UserAgentStat] = {}
        self.stats_file_req: Dict[str, FileRequestStat] = {}
        self.stats_username: Dict[str, int] = defaultdict(int)
        self.stats_file_count: Dict[str, int] = defaultdict(int)

        self.normal_req_pattern = re.compile(AppConfig.REGEX_NORMAl_REQ, re.IGNORECASE)

    def process_file(self, file_path: str):
        with open(file_path, "r", encoding=AppConfig.ENCODING_READ) as f:
            for line in f:
                entry = self.parser.parse_line(line)
                if not entry:
                    continue

                self._analyze_file_request(entry)
                self._analyze_anomaly(entry)
                self._analyze_ip(entry)
                self._analyze_user_agent(entry)
                self._analyze_username(entry)

    def _analyze_file_request(self, entry: LogEntry):
        if isinstance(self.parser, IISParser):
            self._analyze_file_request_iis(entry)
        elif isinstance(self.parser, ApacheParser):
            self._analyze_file_request_apache(entry)

    def _analyze_file_request_iis(self, entry: LogEntry):
        filename_request = entry.filename
        param = entry.param
        url_request = entry.url
        method = entry.method
        status = entry.status
        time_request = entry.time_request

        if not filename_request:
            return

        index_last_dot = filename_request.rfind(".")
        index_filename = filename_request.rfind("/")
        filename = filename_request[index_filename + 1 :]
        is_success_now = HttpDefinitions.classify_success_or_fail(status)
        # if exist, update first to save time
        if self.stats_file_req.get(url_request):
            stat = self.stats_file_req[url_request]
            stat.count += 1
            if is_success_now:
                stat.count_success += 1
            else:
                stat.count_fail += 1
            if method.lower() == "post":
                stat.post += 1
            return

        if index_last_dot != -1 and HttpDefinitions.is_valid_web_exts(filename):
            extension = filename_request[index_last_dot + 1 :]
            self.stats_file_req[url_request] = FileRequestStat(
                time_request=time_request,
                post=(1 if method.lower() == "post" else 0),
                filename=filename,
                count=1,
                extension=extension,
                param=param,
                filename_request=filename_request,
                count_success=(1 if is_success_now else 0),
                count_fail=(0 if is_success_now else 1),
            )

    def _analyze_file_request_apache(self, entry: LogEntry):
        url = entry.url
        if url is None:
            return

        # if exist, update first to save time
        stat = self.stats_file_req.get(url)
        if stat:
            is_success_now = HttpDefinitions.classify_success_or_fail(entry.status)
            stat.count += 1
            if is_success_now:
                stat.count_success += 1
            else:
                stat.count_fail += 1
            if entry.method and entry.method.lower() == "post":
                stat.post += 1
            return

        is_success_now = HttpDefinitions.classify_success_or_fail(entry.status)

        # use urlparse to optimize code
        parsed = urllib.parse.urlparse(url)
        # this is path file, not contain param or fragment
        path = parsed.path

        if not path:
            return

        valid_ext = HttpDefinitions.is_valid_web_exts(path)
        if valid_ext and self.normal_req_pattern.search(path) is not None:
            full_filename = os.path.basename(path)
            index_dot = full_filename.rfind(".")

            if index_dot != -1:
                filename = full_filename
                extension = full_filename[index_dot + 1 :]
                query_param = parsed.query if parsed.query else None
                filename_request = path

                self.stats_file_req[url] = FileRequestStat(
                    time_request=entry.time_request,
                    post=(1 if entry.method.lower() == "post" else 0),
                    filename=filename,
                    count=1,
                    extension=extension,
                    param=query_param,
                    filename_request=filename_request,
                    count_success=(1 if is_success_now else 0),
                    count_fail=(0 if is_success_now else 1),
                )
                self.stats_file_count[filename] = 0

    def _analyze_ip(self, entry: LogEntry):
        if not entry.ip:
            return
        ip = entry.ip.split(":")[0]
        if ip not in self.stats_ip:
            self.stats_ip[ip] = IPStat(
                first_time=entry.time_request, last_time=entry.time_request
            )

        st = self.stats_ip[ip]
        st.total += 1
        st.last_time = entry.time_request
        is_success = HttpDefinitions.classify_success_or_fail(entry.status)
        if is_success:
            st.success += 1
        else:
            st.fail += 1

    def _analyze_user_agent(self, entry: LogEntry):
        ua = entry.user_agent
        if ua and ua != "-" and ua != "":
            if ua not in self.stats_ua:
                self.stats_ua[ua] = UserAgentStat()
            self.stats_ua[ua].count += 1
        # filter request no user agent
        else:
            self.writer.write_no_ua(entry.raw_line)

    def _analyze_username(self, entry: LogEntry):
        if entry.username is not None:
            self.stats_username[entry.username] += 1

    def _is_url_too_long(self, url: str, threshold: int = 500) -> bool:
        if not url:
            return False
        return len(url) > threshold

    def _is_too_many_params(self, url: str, threshold: int = 10) -> bool:
        if not url:
            return False
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.query:
                return False

            params = urllib.parse.parse_qsl(parsed.query)
            return len(params) > threshold
        except Exception:
            return False

    def _write_anomaly_log(self, entry, url, decoded_url, type_attack=""):
        if not type_attack:
            type_attack = self.scanner.dispatcher(decoded_url, entry)

        self.writer.write_attack(
            [
                entry.status,
                HttpDefinitions.classify_success_or_fail(entry.status),
                entry.ip,
                url,
                entry.time_request,
                type_attack,
                entry.user_agent,
            ]
        )

    def _analyze_anomaly(self, entry: LogEntry):
        url = entry.url
        if not url:
            return

        for scheme in ["https://", "http://"]:
            if url.startswith(scheme):
                url = url[len(scheme) :]

        decoded_url = self.scanner.decode_url(url)
        if self.scanner.detect_false_positive(decoded_url):
            return

        # check 3 signature of attack request
        if self._is_url_too_long(url):
            self._write_anomaly_log(entry, url, "", "url_long")
            return
        if self._is_too_many_params(url):
            self._write_anomaly_log(entry, url, "", "many_param")
            return
        if not self.normal_req_pattern.match(url):
            self._write_anomaly_log(entry, url, decoded_url)
            return

    def finalize_export(self):
        for stat in self.stats_file_req.values():
            self.stats_file_count[stat.filename] += stat.count

        self.writer.flush_buffers()
        self.writer.export_dictionaries(
            self.stats_ip,
            self.stats_file_req,
            self.stats_username,
            self.stats_ua,
            self.stats_file_count,
        )
        self.writer.convert_to_excel()


# ==========================================
# MAIN APP
# ==========================================
class LogStatixApp:
    def _guess_mode(self, path_extract: str) -> str:
        iis_header = re.compile(r"^#(Fields|Software|Version|Date):", re.IGNORECASE)
        iis_line = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+")
        apache_parser = ApacheParser()
        apache_patterns = (
            apache_parser._pattern_custom,
            apache_parser._pattern_custom_no_tz,
            apache_parser._pattern_combined,
        )

        iis_score = 0
        apache_score = 0
        max_lines = 200
        lines_checked = 0

        for root, _, files in os.walk(path_extract):
            if "result" in root:
                continue
            for file in files:
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, "r", encoding=AppConfig.ENCODING_READ, errors="ignore") as f:
                        for line in f:
                            if lines_checked >= max_lines:
                                break
                            stripped = line.strip()
                            if not stripped:
                                continue
                            lines_checked += 1

                            if iis_header.match(stripped) or iis_line.match(stripped):
                                iis_score += 2
                            if any(p.match(stripped) for p in apache_patterns):
                                apache_score += 2

                            if iis_score >= 4 or apache_score >= 4:
                                break
                except OSError:
                    continue
            if lines_checked >= max_lines or iis_score >= 4 or apache_score >= 4:
                break

        if iis_score == 0 and apache_score == 0:
            print("[!] Unable to detect log format; defaulting to Apache.")
            return "2"

        if iis_score >= apache_score:
            print("[+] Detected IIS log format.")
            return "1"

        print("[+] Detected Apache log format.")
        return "2"

    def run(self, path_zip: Optional[str] = None, mode: Optional[str] = None):
        print("Remember change order of columns if select type Apache. Please find #Dangerous in code to change")

        if not path_zip:
            path_zip = input("Input path file zip or directory: ").strip('"')
        else:
            path_zip = path_zip.strip('"')

        start_time = time.time()
        if not os.path.exists(path_zip):
            print(f"[!] Path not found: {path_zip}")
            return

        if os.path.isdir(path_zip):
            path_extract = path_zip
            print(f"[+] Using directory: {path_extract}")
        else:
            path_extract = FileUtils.unzip_file(path_zip)
            print(f"[+] Extracted to: {path_extract}")

        if not mode:
            mode = self._guess_mode(path_extract)
        else:
            mode = mode.strip().lower()
            if mode in ("iis", "1"):
                mode = "1"
            elif mode in ("apache", "2"):
                mode = "2"

        scanner = ScannerVulnerability()
        writer = ReportWriter(path_extract)

        parser = None
        if mode == "1":
            parser = IISParser()
        elif mode == "2":
            parser = ApacheParser()
        else:
            return

        analyzer = LogAnalyzer(parser, scanner, writer)

        print("[+] Processing logs...")
        for root, _, files in os.walk(path_extract):
            if "result" in root:
                continue
            for file in files:
                full_path = os.path.join(root, file)
                analyzer.process_file(full_path)

        analyzer.finalize_export()
        print(f"[+] Complete in {time.time() - start_time:.2f} seconds")


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="LogStatix analyzer")
    arg_parser.add_argument(
        "--zip", dest="path_zip", help="Path to log ZIP file or directory"
    )
    arg_parser.add_argument(
        "--mode",
        choices=["1", "2", "iis", "apache"],
        help="Log type (1/ iis, 2/ apache)",
    )
    args = arg_parser.parse_args()

    app = LogStatixApp()
    app.run(path_zip=args.path_zip, mode=args.mode)
