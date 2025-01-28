# LogStatix
A powerful and efficient tool to parse and analyze web server logs for IIS and Apache. This tool is designed for security analysts and administrators to detect suspicious activities, analyze traffic, and extract useful statistics from server logs.

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
