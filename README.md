# LogStatix
## Features
### 1. Filter Attack Requests
* Detects and filters malicious requests, including:
    * SQL Injection attempts.
    * Cross-Site Scripting (XSS) payloads.
    * Command Injection attempts, etc
* Provides actionable insights to identify and mitigate potential threats.

### 2. Filter User-Agent
* Categorizes user agents into:
    * Official User Agents: Recognized browsers such as Mozilla Firefox, Google Chrome, Safari, etc.
    * Non-Official User Agents: Scripts and tools like Python, curl, Wget, etc.
* Helps distinguish between legitimate traffic and automated/malicious activity.

### 3. IP Request Statistics
* Tracks IP addresses making requests to the server.
* Provides statistics for each IP, including:
    * Total Requests.
    * Successful Requests.
    * Failed Requests.
 
### 4. Request File Statistics
* Analyzes file access patterns to detect anomalies:
    * Examines parameters of GET requests for potential webshell activities.
    * Tracks the number of POST requests.
    * Identifies files that are accessed too frequently (indicating possible abuse).
    * Flags files that could potentially be webshells.
    * Facilitates forensic analysis by highlighting suspicious file usage.
 
### 5. Username Statistics
* Tracks and provides statistics on usernames found in the logs.
* Helps identify suspicious login attempts or compromised accounts.

## Usage
### Install
```
pip install -r requirements.txt
```

### Run
```
python LogStatix.py --zip "path\to\logs.zip"
python LogStatix.py --zip "path\to\log_dir" --mode apache
```

Notes:
- `--mode` accepts `iis`, `apache`, `1`, or `2`. If omitted, LogStatix auto-detects.
- Output is written to `result/report.xlsx` under the input directory.

## Development
```
pip install -r requirements-dev.txt
ruff check .
pytest
```