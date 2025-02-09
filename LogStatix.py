import html
import os
import re
from datetime import datetime
from zipfile import ZipFile
import csv
import time
import urllib.parse
from collections import deque


class UserAgent:
    def __init__(self):
        self.count = 1

    def increase_count(self):
        self.count += 1


class IP:
    def __init__(self, fail, success, total):
        self.fail = fail
        self.success = success
        self.total = total

    def increase_fail(self):
        self.fail += 1

    def increase_success(self):
        self.success += 1

    def increase_total(self):
        self.total += 1


class FileRequest:
    def __init__(self, time_request, post, filename, count, extension, param, filename_request, success):
        self.time_request = time_request
        self.post = post
        self.filename = filename
        self.count = count
        self.extension = extension
        self.param = param
        self.filename_request = filename_request
        self.success = success

    def increase_count(self):
        self.count += 1

    def increase_post(self):
        self.post += 1


class ManipulationFiles:
    def __init__(self):
        self.format_datetime = '%d%m%Y_%H%M%S%f'
        self.encoding = 'UTF-8'

    def unzip(self, path_archive: str) -> str:
        zf = ZipFile(path_archive, 'r')
        folder_name = os.path.split(path_archive)[0]
        curr_time = datetime.now().strftime(self.format_datetime)
        path_extract = os.path.join(folder_name, 'log_' + str(curr_time))
        zf.extractall(path_extract)
        zf.close()
        return path_extract

    # write log into csv
    def write_log_csv(self, path_log: str, content: deque):
        f = open(path_log, 'a', encoding=self.encoding, newline='')
        writer = csv.writer(f)
        writer.writerows(content)

    # write log into txt
    def write_log_txt(self, path_log: str, content: str):
        f = open(path_log, 'a', encoding=self.encoding, newline='')
        f.write(content)
        f.close()


class Export:
    list_user_agent = {}
    list_user_agent_non_official = {}
    list_ip = {}
    list_file_request = {}
    list_username = {}
    list_file_count = {}

    def __init__(self):
        self.manipulation_file = ManipulationFiles()
        self.path_user_agent = 'result\\user_agent_official.csv'
        self.path_user_agent_non_official = 'result\\user_agent_non_official.csv'
        self.path_statistic_ip = 'result\\statistic_ip.csv'
        self.path_file_request = 'result\\file_request.csv'
        self.path_file_request_2 = 'result\\file_request_count.csv'
        self.path_username = 'result\\username.csv'
        self.batch_size = 1000
        # deque() for higher performance pop than list
        self.buffer = deque()

    # restrict write continuously into disk, use batch_size to check
    def export_remain(self, path_log: str):
        if self.buffer:
            self.manipulation_file.write_log_csv(path_log, self.buffer)
            self.buffer.clear()

    def export_user_agent(self, path_extract: str):
        # official user-agent
        content = [['UserAgent', 'Count']]
        path_log_official = os.path.join(path_extract, self.path_user_agent)
        self.manipulation_file.write_log_csv(path_log_official, content)
        # Non official user-agent
        path_log_non_official = os.path.join(path_extract, self.path_user_agent_non_official)
        self.manipulation_file.write_log_csv(path_log_non_official, content)
        for user_agent, count in self.list_user_agent.items():
            if user_agent is not None and user_agent.startswith('Mozilla'):
                self.buffer.append([user_agent, count.count])
                if len(self.buffer) >= self.batch_size:
                    self.manipulation_file.write_log_csv(path_log_official, self.buffer)
                    self.buffer.clear()
            else:
                self.manipulation_file.write_log_csv(path_log_non_official, [[user_agent, count.count]])
        self.export_remain(path_log_official)

    def export_statistic_ip(self, path_extract: str):
        content = [['IP', 'Fail', 'Success', 'Total']]
        path_log = os.path.join(path_extract, self.path_statistic_ip)
        self.manipulation_file.write_log_csv(path_log, content)
        for ip, status in self.list_ip.items():
            self.buffer.append([ip, status.fail, status.success, status.total])
            if len(self.buffer) >= self.batch_size:
                self.manipulation_file.write_log_csv(path_log, self.buffer)
                self.buffer.clear()
        self.export_remain(path_log)

    def export_statistic_file_request(self, path_extract: str):
        header = [['time', 'post', 'filename', 'count', 'extension', 'param', 'file_request', 'url', 'success']]
        path_log = os.path.join(path_extract, self.path_file_request)
        self.manipulation_file.write_log_csv(path_log, header)
        for url_request, statistic in self.list_file_request.items():
            # Statistic count of per file request
            Export.list_file_count[statistic.filename] += statistic.count
            self.buffer.append([statistic.time_request, statistic.post, statistic.filename, statistic.count, statistic.extension, statistic.param,
                       statistic.filename_request, url_request, statistic.success])
            if len(self.buffer) >= self.batch_size:
                self.manipulation_file.write_log_csv(path_log, self.buffer)
                self.buffer.clear()
        self.export_remain(path_log)

    # write statistic count of per file request
    def export_statistic_file_request_2(self, path_extract: str):
        header = [['filename', 'count']]
        path_log = os.path.join(path_extract, self.path_file_request_2)
        self.manipulation_file.write_log_csv(path_log, header)
        for filename, count in self.list_file_count.items():
            self.manipulation_file.write_log_csv(path_log, [[filename, count]])

    def export_username(self, path_extract: str):
        header = [['username', 'count']]
        path_log = os.path.join(path_extract, self.path_username)
        self.manipulation_file.write_log_csv(path_log, header)
        for username, count in self.list_username.items():
            self.buffer.append([username, count])
            if len(self.buffer) >= self.batch_size:
                self.manipulation_file.write_log_csv(path_log, self.buffer)
                self.buffer.clear()
        self.export_remain(path_log)


class Utility:
    def __init__(self):
        self.success = ['200', '201', '202', '203', '204', '205', '206', '207', '208', '226']
        self.redirection = ['300', '301', '302', '303', '304', '305', '306', '307', '308']
        self.client_error = ['400', '401', '402', '403', '404', '405', '406', '407', '408', '409', '410', '411', '412',
                             '413', '414', '415', '416', '417', '418', '421', '422', '423', '424', '425', '426', '428',
                             '429', '431', '451']
        self.server_error = ['500', '501', '502', '503', '504', '505', '506', '507', '508', '510', '511']
        self.extension = ('.php', '.xml', '.java', '.aspx', '.axd', '.asp', '.py', '.rb', '.jsp', '.js', '.jspx', '.sh', '.jar', '.cgi', '.ashx', '.ascx', '.asmx', '.eas')
        self.warning = 'Remember change order of columns if select type Apache. Please find #Dangerous in code to change'

    # classify request is success (200,...) or fail (400, 500,...)
    def classify_success_or_fail(self, status: str):
        if status in self.success:
            return True
        elif status in self.redirection:
            return True
        elif status in self.client_error:
            return False
        elif status in self.server_error:
            return False
        else:
            return None

    def check_valid_file_extension(self, request: str) -> bool:
        return True if request.endswith(self.extension) else False

    def input_mode_path(self) -> int:
        print(self.warning)
        path_zip = input('Input path file zip: ').strip('"')
        print('1. IIS')
        print('2. Apache')
        selection_mode = input('Please choice: ')
        match selection_mode:
            case '1':
                return 1, path_zip
            case '2':
                return 2, path_zip


class ScannerVulnerability:
    def __init__(self):
        #  Compile regex patterns once at the beginning and reuse them to save compilation time.
        self.sql_injection_patterns = [
            r"union.*select",
            r"select.*from",
            r"insert\s+into.*values",
            r"update.*set",
            r"delete\s+from",
            r"drop\s+table",
            r"alter\s+table",
            r"create\s+table",
            r"shutdown",
            r"'\s+or\s+'1'='1",
            r"\"\s+or\s+\"1\"=\"1",
            r"or\s+\d+=\d+",
            r"exec\s+xp_",
            r"sp_executesql",
            r"benchmark\((.*)\,(.*)\)",
            r"sleep\(([\d\+\*\-]+)\)",
            r"md5\(([0-9a-zA-Z]+)\)",
            r"load_file\(",
            r"base64_decode\(",
            r"into\s+outfile",
            r"information_schema",
            r"master..sysdatabases",
            r"current_user",
            r"version\(\)",
            r"char\(",
            r"chr\(",
            r"cast\(",
            r"convert\(",
            r"concat\(",
            r"substring\(",
            r"hex\(",
            r"ascii\(",
            r"order\s+by\s+\d+",
            r"group\s+by\s+",
            r"like\s+'.*%'",
            r"\/\*.*?\*\/",
            r"0x[0-9a-f]+",
            r"\bwaitfor\b",
            r"\s+and\s+",
            r"\s+or\s+",
            r"'\|\|'",
        ]
        self.compiled_sql_injection_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_injection_patterns]
        self.xss_patterns = [
            r"<script.*?>.*?</script>",
            r"<.*?javascript:.*?>",
            r"<.*?on\w+\s*=\s*['\"].*?>",
            r"<iframe.*?>.*?</iframe>",
            r"<img.*?(src|onmouseover)(\s*)?=(\s*)?.*?>",
            r"<.*?style.*?>.*?expression\(.*?\).*?>",
            r"<.*?vbscript:.*?>",
            r"document\.cookie",
            r"document\.location",
            r"window\.location",
            r"document\.write\(",
            r"alert\(",
            r"eval\(",
            r"prompt\(",
            r"on\w+\s*=\s*['\"].*?(alert|eval|prompt)\(",
            r"on\w+\s*=\s*['\"].*?window\.",
            r"on\w+\s*=\s*['\"].*?document\.",
            r"<link.*?href\s*=\s*['\"].*?javascript:.*?>",
            r"<.*?src\s*=\s*['\"]\s*data:text\/html;base64,",
            r"<object.*?>.*?</object>",
            r"<embed.*?>.*?</embed>",
            r"<meta.*?http-equiv\s*=\s*['\"]refresh['\"]",
            r"<svg.*?>.*?</svg>",
            r"<base.*?>",
            r"<!--.*?-->",
            r"<audio.*?>.*?</audio>",
            r"<video.*?>.*?</video>",
            r"<marquee.*?>.*?</marquee>",
            r"<body.*?onload.*?>",
            r"<input.*?type\s*=\s*['\"]hidden['\"].*?>",
            r"%3Cscript%3E",
            r"src\s*=\s*[\"']\s*javascript:",
            r"src\s*=\s*[\"']\s*vbscript:",
            r"style\s*=\s*[\"'].*?expression\(",
            r"\balert\b",
            r"\bconfirm\b",
            r"\bon\w+\s*=\s*[\"'].*?>",
            r"<\w+\s+[^>]*?on\w+\s*=\s*[\"'].*?>",
            r"\bsrcdoc\s*=\s*['\"].*<script>.*</script>",
            r"\bdocument\.(URL|documentURI|baseURI)",
            r"<\s*meta\s+.*?content\s*=\s*['\"]\d+;\s*url=['\"].*?['\"]",
            r"data:text/html;base64,",
            r"java\s*script:",
            r"<\s*\w+\s*.*?src\s*=\s*['\"].*?data:text/html",
            r"<\s*svg\s*.*?on\w+\s*=",
            r"on\w+\s*=\s*`.*`",
            r"\bwindow\.\w+\s*\(.*\)",
        ]
        self.compiled_xss_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.xss_patterns]
        self.redirection_pattern = [
            r"redirect=",
            r"uri=",
            r"redirectto=",
            r"url=",
            r"to=",
            r"next=",
            r"return=",
            r"dest=",
        ]
        self.compiled_redirection_pattern = [re.compile(pattern, re.IGNORECASE) for pattern in self.redirection_pattern]
        self.path_traversal_patterns = [
            r"\.\.\\",
            r"\./",
            r"\.\\",
            r"\\\.\.\\",
            r"/\.\./",
            r"\\",
            r"=\w:/",
            r"/etc/passwd",
            r"/etc/shadow",
            r"/etc/group",
            r"/proc/self/environ",
            r"boot\.ini",
            r"\bwin\.ini\b",
            r"system32",
            r"cmd\.exe",
            r"powershell\.exe",
            r"windows\\system32",
            r"\\boot\\",
            r"\\windows\\",
            r"\b\w:\\",
            r"file://",
            r"php://",
            r"zlib://",
            r"expect://",
            r"data://",
            r"input://",
            r"dir",
        ]
        self.compiled_path_traversal_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.path_traversal_patterns]
        self.command_injection_patterns = [
            r"\bsh\b",
            r"\bbash\b",
            r"\bcmd\b",
            r"\bpowerShell\b",
            r"\bperl\b",
            r"\bpython\b",
            r"\bcurl\b",
            r"\bwget\b",
            r"\bnetcat\b",
            r"\bnc\b",
            r"\btelnet\b",
            r"\bftp\b",
            r"\bscp\b",
            r"\bssh\b",
            r"\bnslookup\b",
            r"\bnmap\b",
            r"\bwhoami\b",
            r"\bhostname\b",
            r"\bifconfig\b",
            r"\bipconfig\b",
            r"\bping\b",
            r"\btraceroute\b",
            r"\bnmap\b",
            r"\bkill\b",
            r"\bpkill\b",
            r"\bkillall\b",
            r"\bchmod\b",
            r"\bchown\b",
            r"\bchgrp\b",
            r"\btouch\b",
            r"\brm\b",
            r"\bmkdir\b",
            r"\brmdir\b",
            r"\bcurl\b",
            r"\bftp\b",
            r">\s*/dev/null",
            r">\s*2>&1",
        ]
        self.compiled_command_injection_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.command_injection_patterns]
        self.security_misconfiguration_patterns = [
            r"/\.git/",
            r"/\.svn/",
            r"/\.hg/",
            r"/\.DS_Store",
            r"/\.env",
            r"/\.htaccess",
            r"/\.htpasswd",
            r"/\.",
            r"~/",
            r"/config\.php",
            r"/web\.config",
            r"/nginx\.conf",
            r"/httpd\.conf",
            r"/server-status",
            r"/phpinfo\.php",
            r"/wp-config\.php",
            r"/backup/",
            r"/temp/",
            r"/test/",
            r"\bdebug=true\b",
            r"\btrace=true\b",
            r"\btest=true\b",
            r"/dashboard/",
            r"/phpMyAdmin",
            r"/admin-console",
            r"/jmx-console",
            r"/manager/html",
            r"admin/",
            r"admin\.",
        ]
        self.compiled_security_misconfiguration_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.security_misconfiguration_patterns]
        self.exchange_pattern = [
            r'.*autodiscover\.json.*\@.*Powershell.*',
            r'.*autodiscover\.json.*\@.*'
        ]
        self.compiled_exchange_pattern = [re.compile(pattern, re.IGNORECASE) for pattern in self.exchange_pattern]
        self.false_pattern = [
            # r'=<empty>',
            # r'\?Cmd=Ping&',
            # r'\?Cmd=Options&',
            # r'\?Cmd=FolderSync&',
            # r'\?Cmd=Sync&',
            # r'\?Cmd=Search&',
            # r'\?MailboxId\=[0-9a-f\-]+\@[a-zA-Z0-9\.]+',
            # r'/WebResource.axd\?d=',
            # r'/ScriptResource.axd\?d=',
        ]
        self.compiled_false_pattern = [re.compile(pattern, re.IGNORECASE) for pattern in self.false_pattern]
        self.compiled_hex_encoding = re.compile(r'%[0-9a-fA-F]{2}')
        self.compiled_hex_encoding_2 = re.compile(r'x[0-9a-fA-F]{2}')
        self.complied_break_line = re.compile(r'\r\n')
        self.compiled_unicode_encoding = re.compile(r'\\u[0-9a-fA-F]{4}')

    def decode_url(self, line: str) -> str:
        # URL decode
        decoded_line = urllib.parse.unquote(line)
        decoded_line = html.unescape(decoded_line)
        # Remove NULL
        decoded_line = decoded_line.replace('\x00', ' ')
        decoded_line = re.sub(r'x1a', '', decoded_line)
        # Decode potential hexadecimal encodings
        decoded_line = self.compiled_hex_encoding.sub(lambda x: chr(int(x.group(0)[1:], 16)), decoded_line)
        decoded_line = self.compiled_hex_encoding_2.sub(lambda x: chr(int(x.group(0)[1:], 16)), decoded_line)
        # Decode potential Unicode encodings (e.g., \u003C)
        decoded_line = self.compiled_unicode_encoding.sub(lambda x: chr(int(x.group(0)[2:], 16)), decoded_line)
        # Remove break line
        decoded_line = self.complied_break_line.sub('', decoded_line)
        return decoded_line

    def detect_sql_injection(self, line: str) -> bool:
        for pattern in self.compiled_sql_injection_patterns:
            if pattern.search(line, re.IGNORECASE) is not None:
                return True
        return False

    def detect_xss(self, line: str) -> bool:
        for pattern in self.compiled_xss_patterns:
            if pattern.search(line, re.IGNORECASE) is not None:
                return True
        return False

    def detect_command_injection(self, line: str) -> bool:
        for pattern in self.compiled_command_injection_patterns:
            if pattern.search(line, re.IGNORECASE) is not None:
                return True
        return False

    def detect_path_traversal(self, line: str) -> bool:
        for pattern in self.compiled_path_traversal_patterns:
            if pattern.search(line, re.IGNORECASE) is not None:
                return True
        return False

    def detect_security_misconfiguration(self, line) -> bool:
        for pattern in self.compiled_security_misconfiguration_patterns:
            if pattern.search(line, re.IGNORECASE) is not None:
                return True
        return False

    def detect_exchange_vulnerability(self, line) -> bool:
        for pattern in self.compiled_exchange_pattern:
            if pattern.search(line, re.IGNORECASE):
                return True
        return False

    def detect_false_positive(self, line) -> bool:
        for pattern in self.compiled_false_pattern:
            if pattern.search(line):
                return True
        return False

    def detect_url_redirection(self, line) -> bool:
        for pattern in self.compiled_redirection_pattern:
            if pattern.search(line):
                return True
        return False

    def dispatcher(self, line: str) -> str:
        if self.detect_exchange_vulnerability(line):
            return 'exchange_vuln'
        elif self.detect_sql_injection(line):
            return 'sql-injection'
        elif self.detect_xss(line):
            return 'xss'
        elif self.detect_url_redirection(line):
            return 'redirection'
        elif self.detect_command_injection(line):
            return 'command-injection'
        elif self.detect_path_traversal(line):
            return 'path-traversal'
        elif self.detect_security_misconfiguration(line):
            return 'security-misconfiguration'
        else:
            return ''


class CoreFunctionality:
    def __init__(self):
        self.utilities = Utility()
        self.export = Export()
        self.scanner = ScannerVulnerability()
        self.manipulation_file = ManipulationFiles()
        self.path_request_attack = 'result\\attack_request.csv'
        self.path_no_user_agent = 'result\\no_user_agent.txt'
        self.normal_request = re.compile(r'^[a-zA-Z0-9;/&.,?+=_-]+$')

    # write header of feature 1, prevent if else to check per line
    def write_header_attack_request(self, path_extract: str):
        path_log = os.path.join(path_extract, self.path_request_attack)
        content = [['Status', 'Success', 'IP', 'Url', 'Datetime', 'Type', 'UserAgent']]
        self.manipulation_file.write_log_csv(path_log, content)

    # Feature 1: Filter anomaly request
    # Because of over ram if save into list object and write to file later, we need write it directly, no need to save list object
    def filter_export_anomaly_request(self, url: str, ip: str, status: str, time_request: str, user_agent: str, path_extract: str):
        path_log = os.path.join(path_extract, self.path_request_attack)
        if url.startswith('https://') or url.startswith('http://'):
            url = url.strip('https://')
            url = url.strip('http://')
        if url:
            if self.normal_request.match(url):
                decoded_url = url
            else:
                decoded_url = self.scanner.decode_url(url)
        
            if not self.normal_request.match(decoded_url) and not self.scanner.detect_false_positive(decoded_url):
                type_attack = self.scanner.dispatcher(decoded_url)
                if len(self.export.buffer) >= self.export.batch_size:
                    self.manipulation_file.write_log_csv(path_log, self.export.buffer)
                    self.export.buffer.clear()
                else:
                    content = [status, self.utilities.classify_success_or_fail(status), ip, url, time_request,
                                type_attack, user_agent]
                    self.export.buffer.append(content)
        self.export.export_remain(path_log)

    # Feature 2: List unique user agent and count
    # Because we need to classify unique of user agent so cannot write it directly to file. If we write to file, we cannot count times of user agent
    def filter_unique_useragent(self, user_agent: str, line: str, path_extract: str):
        if user_agent or user_agent != '' or user_agent != '-':
            if Export.list_user_agent.get(user_agent) is None:
                Export.list_user_agent[user_agent] = UserAgent()
            else:
                Export.list_user_agent[user_agent].increase_count()
        else:
            self.manipulation_file.write_log_txt(os.path.join(path_extract, self.path_no_user_agent), line)

    # Feature 3: Statistic ip request: success, fail,...
    def statistic_ip(self, ip: str, status: str):
        success_or_fail = self.utilities.classify_success_or_fail(status)
        if ip.find(':') != -1:
            ip = ip.split(':')[0]
        if Export.list_ip.get(ip) is None:
            Export.list_ip[ip] = IP(0, 0, 0)
        Export.list_ip[ip].increase_total()
        if success_or_fail:
            Export.list_ip[ip].increase_success()
        else:
            Export.list_ip[ip].increase_fail()

    # Feature 5: Statistic authentication username
    def enumerate_username(self, username: str):
        if Export.list_username.get(username) is None:
            Export.list_username[username] = 1
        else:
            Export.list_username[username] += 1


class IIS(CoreFunctionality):
    def __init__(self):
        super().__init__()
        self.index_column_iis = {}

    # Split column in IIS via describable cmt type line of IIS Server
    def identify_column(self, line: str):
        if line.find('#Fields: ') == 0:
            column_name = line[10:].split()
            for index, column in enumerate(column_name):
                match column:
                    case 'ate':
                        self.index_column_iis['date'] = index
                    case 'date':
                        self.index_column_iis['date'] = index
                    case 'time':
                        self.index_column_iis['time'] = index
                    case 'cs-uri-stem':
                        self.index_column_iis['cs-uri-stem'] = index
                    case 'cs-uri-query':
                        self.index_column_iis['cs-uri-query'] = index
                    case 'c-ip':
                        self.index_column_iis['c-ip'] = index
                    case 'cs(User-Agent)':
                        self.index_column_iis['cs(User-Agent)'] = index
                    case 'sc-status':
                        self.index_column_iis['sc-status'] = index
                    case 'cs(Referer)':
                        self.index_column_iis['cs(Referer)'] = index
                    case 'cs-username':
                        self.index_column_iis['cs-username'] = index
                    case 'cs-method':
                        self.index_column_iis['cs-method'] = index
        elif line.find('#') != 0:
            columns = line.split(' ')
            url_request = columns[self.index_column_iis['cs-uri-stem']] + ('?' + columns[self.index_column_iis['cs-uri-query']]) if columns[self.index_column_iis['cs-uri-query']] != '-' else ''
            ip = columns[self.index_column_iis['c-ip']]
            user_agent = columns[self.index_column_iis['cs(User-Agent)']]
            filename = columns[self.index_column_iis['cs-uri-stem']]
            status = columns[self.index_column_iis['sc-status']]
            param = columns[self.index_column_iis['cs-uri-query']]
            time_request = columns[self.index_column_iis['date']] + ' ' + columns[self.index_column_iis['time']]
            referer = columns[self.index_column_iis['cs(Referer)']]
            username = columns[self.index_column_iis['cs-username']]
            method = columns[self.index_column_iis['cs-method']]
            return url_request, ip, user_agent, filename, status, param, time_request, referer, username, method

    # Because column url not have parameter, it in another column, so we don't need to split like apache
    def statistic_filename_request(self, time_request: str, method:str, filename_request: str, param: str, url_request: str, status: str):
        index_last_dot = filename_request.rfind('.')
        index_filename = filename_request.rfind('/')
        filename = filename_request[index_filename+1:]
        if index_last_dot != -1:
            if Export.list_file_request.get(url_request) is None:
                if self.utilities.check_valid_file_extension(filename):
                    extension = filename_request[index_last_dot+1:]
                    Export.list_file_request[url_request] = FileRequest(time_request, 1, filename, 1, extension, param, filename_request, self.utilities.classify_success_or_fail(status))
                    Export.list_file_count[filename] = 0
            elif Export.list_file_request.get(url_request) and method.lower() == 'post':
                # increase post request, maybe upload file
                Export.list_file_request[url_request].increase_post()
                Export.list_file_request[url_request].increase_count()
            else:
                Export.list_file_request[url_request].increase_count()


class Apache(CoreFunctionality):
    def __init__(self):
        super().__init__()
        # %h: client ip
        # %l: The identity of the client as determined by identd (usually "-")
        # %u: The username of the client if authenticated
        # %t: time request
        # %z: zone time
        # %m: method request
        # %r: uri
        # %v: version http
        # %>s: status
        # #Dangerous --> Change order column here
        self.default_format_log = '%h %l %u %t %z %m %r %v %>s %b "%{Referer}i" "%{User-Agent}i"'
        # custom_format_log = 'a %t "%{Referer}i" %h a a a a %>s a a a %m %r %v "%{User-Agent}i"'
        self.valid_extension = re.compile(r'[!-~]+\.(php|xml|java|aspx|asp|py|rb|js|jsp|jspx|sh|jar|cgi|ashx|ascx|asmx)')

    # we use default format log of apache to split column. So it will increase performance than using regex.
    # if it uses custom format log, we change order column in field self.default_format_log of init
    def identify_column(self, line: str):
        parts = line.split()
        ip = referer = uri = status = user_agent = time_request = username = method = None
        fields = self.default_format_log.split()
        for i, f in enumerate(fields):
            if i < len(parts):
                match f:
                    case '%h':
                        ip = parts[i]
                    case '%r':
                        uri = parts[i].strip('"')
                    case '"%{Referer}i"':
                        referer = parts[i].strip('"')
                    case '%>s':
                        status = parts[i]
                    case '"%{User-Agent}i"':
                        j = i
                        start_user_agent = -1
                        while j < len(parts):
                            if parts[j].startswith('"'):
                                start_user_agent = j
                                j += 1
                            elif parts[j].endswith('"') and start_user_agent > 0:
                                user_agent = ' '.join(parts[start_user_agent:j+1]).strip('"')
                                break
                            else:
                                j += 1
                    case '%t':
                        time_request = parts[i].strip('[')
                    case '%u':
                        username = parts[i].strip()
                    case '%m':
                        method = parts[i].strip()
        return ip, referer, uri, status, user_agent, time_request, username, method

    # Feature 4: Statistic request via extension of file
    def statistic_filename_request(self, time_request:str, method:str, url: str, status: str):
        # get only request file, if not skip
        valid_file_extension = self.valid_extension.search(url)
        if valid_file_extension is not None and self.normal_request.search(url) is not None:
            if url is not None:
                # we use dictionary to classify and count unique url
                if Export.list_file_request.get(url) is None:
                    index_param = url.find('?')
                    index_fragment = url.find('#')
                    # Find filename via parameter
                    if index_param != -1:
                        sub_url = url[:index_param]
                        index_last_path = sub_url.rfind('/')
                        file_extension = url[index_last_path+1:index_param]
                        if self.utilities.check_valid_file_extension(file_extension) is False:
                            return
                    # Find filename via fragment
                    elif index_fragment != -1:
                        sub_url = url[:index_fragment]
                        index_last_path = sub_url.rfind('/')
                        file_extension = url[index_last_path+1:index_fragment]
                        if self.utilities.check_valid_file_extension(file_extension) is False:
                            return
                    # If any not found, get last path that is filename
                    else:
                        index_last_path = url.rindex('/')
                        file_extension = url[index_last_path+1:]
                        if self.utilities.check_valid_file_extension(file_extension) is False:
                            return
                    # Get extension of filename, we use reverse find because of double extension or triple extension
                    index_dot_extension = file_extension.rfind('.')
                    if valid_file_extension != -1:
                        index_extension = index_dot_extension + 1
                        # validate index of extension is not out of array string
                        # Because file_extension is only filename, if index_extension it not equal len file_extension that abnormal
                        while index_extension < len(file_extension) and (file_extension[index_extension].isalnum() or file_extension[index_extension] == '.'):
                            index_extension += 1
                        # Check extension that we split from url if it has got extension of webshell
                        if index_extension != len(file_extension) and self.utilities.check_valid_file_extension(file_extension) is False:
                            return
                        # Get param and file request
                        query_param = url[index_last_path+1:]
                        index_param = query_param.find('?')
                        index_file_request = url.find('?')
                        param = filename_request = None
                        if index_param != -1:
                            param = query_param[index_param+1:]
                            filename_request = url[:index_file_request]
                        # ['time_request, post, filename', 'count', 'extension', 'param', 'file_request', 'url', 'success']
                        file_request = FileRequest(time_request, 1, file_extension[:index_extension], 1,
                                                   file_extension[index_dot_extension+1:index_extension], param,
                                                   filename_request, self.utilities.classify_success_or_fail(status))
                        Export.list_file_request[url] = file_request
                        Export.list_file_count[file_extension[:index_extension]] = 0
                elif method.lower() == 'post' and Export.list_file_request.get(url):
                    # increase post request, maybe upload file
                    Export.list_file_request[url].increase_post()
                    Export.list_file_request[url].increase_count()
                else:
                    Export.list_file_request[url].increase_count()


class Main:
    def __init__(self):
        self.apache = Apache()
        self.iis = IIS()
        self.utilities = Utility()
        self.manipulation_files = ManipulationFiles()
        self.export = Export()

    def run(self):
        selection_mode, path_zip = self.utilities.input_mode_path()
        # Zip file to parse multiple log
        start = time.time()
        # prepare env
        path_extract = self.manipulation_files.unzip(path_zip)
        os.mkdir(os.path.join(path_extract, 'result'))
        # write header feature 1 
        self.apache.write_header_attack_request(path_extract)
        if path_extract is not None:
            for root, d_names, f_names in os.walk(path_extract):
                # skip folder result
                if root.find('\\result') != -1:
                    continue
                for f in f_names:
                    path_log = os.path.join(root, f)
                    file_log = open(path_log, 'r', encoding='cp437')
                    for line in file_log.readlines():
                        match selection_mode:
                            # IIS
                            case 1:
                                columns = self.iis.identify_column(line)
                                if columns is not None:
                                    url, ip, user_agent, filename, status, param, time_request, referer, username, method = columns[0], columns[1], columns[2], columns[3], columns[4], columns[5], columns[6], columns[7], columns[8], columns[9]
                                    self.iis.filter_export_anomaly_request(url, ip, status, time_request, user_agent, path_extract)
                                    self.iis.statistic_ip(ip, status)
                                    self.iis.filter_unique_useragent(user_agent, line, path_extract)
                                    self.iis.statistic_filename_request(time_request, method, filename, param, url, status)
                                    self.iis.enumerate_username(username)
                            # Apache
                            case 2:
                                ip, referer, url, status, user_agent, time_request, username, method = self.apache.identify_column(line)
                                self.apache.filter_export_anomaly_request(url, ip, status, time_request, user_agent, path_extract)
                                self.apache.filter_unique_useragent(user_agent, line, path_extract)
                                self.apache.statistic_ip(ip, status)
                                self.apache.statistic_filename_request(time_request, method, url, status)
                                self.apache.enumerate_username(username)
        # export
        self.export.export_user_agent(path_extract)
        self.export.export_statistic_ip(path_extract)
        self.export.export_statistic_file_request(path_extract)
        self.export.export_statistic_file_request_2(path_extract)
        self.export.export_username(path_extract)
        print(f'Complete {time.time()-start}')


if __name__ == '__main__':
    main = Main()
    main.run()
