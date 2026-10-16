# Log Analyzer

A Python-based cybersecurity tool designed to parse server logs, detect suspicious access patterns, and identify potential security events.

## Features

- Parse raw HTTP/server access logs
- Detect failed login attempts
- Count failed login attempts by IP address
- Identify suspicious IP addresses
- Use a configurable suspicious IP threshold
- Count HTTP status codes
- Count requested paths
- Identify the IP address with the most failed login attempts
- Generate a security summary
- Generate a text-based security report
- Generate a JSON security report
- Safely ignore malformed log lines

## Technologies Used

- Python 3
- Git
- GitHub
- JSON
- Unit Testing with Python `unittest`

## Setup & Usage

Clone the repository and move into the project directory.

```bash
git clone https://github.com/Asilindile06/log-analyzer.git
cd log-analyzer

## How the Log Analyzer Works

```text
Server Logs
     |
     v
Read Log File
     |
     v
Parse Log Entries
     |
     v
Analyze Log Data
     |
     +-------------------+
     |                   |
     v                   v
Failed Logins       HTTP Statistics
     |
     v
Count Failed Logins by IP
     |
     v
Identify Suspicious IPs
     |
     v
Generate Security Summary
     |
     +-------------------+
     |                   |
     v                   v
Text Report         JSON Report


WTC-3JHACMZH