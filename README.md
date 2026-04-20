# Multilingual Log Analysis

A Python-based security log analysis project for identifying language-related attack patterns in server logs.

## Overview

This project focuses on security log analysis with multilingual awareness.

Instead of treating logs as plain text, it identifies:
- suspicious patterns in HTTP requests
- common attack vectors (e.g. admin panels, login endpoints)
- multilingual and encoded payloads (including Cyrillic)

The goal is to provide a simple but effective way to interpret real-world attack traffic.

## Why this project exists

Most log analysis focuses on IPs, status codes, and endpoints.

This project adds another layer:
**language-aware analysis**.

That means:
- detecting Cyrillic-based payloads
- spotting multilingual login attempts
- highlighting suspicious keywords from Russian/Ukrainian contexts
- making attack traffic easier to interpret

## Features

- Parses log files line by line
- Detects Cyrillic characters
- Scores likely language category:
  - `ru_or_ua`
  - `latin_only`
  - `mixed`
  - `unknown`
- Detects suspicious security-related keywords
- Produces a summary report in JSON
- extracts frequently requested paths from real Nginx access logs
- highlights suspicious probes such as `/.git/config`, `/etc/passwd`, and admin/login endpoints

## Current status

Initial working prototype.

## Usage

```bash
python3 src/analyzer.py /var/log/nginx/access.log --output output/nginx_report.json
```
```bash
python3 src/analyzer.py sample_logs/nginx_access_sample.log --output output/report.json
```
## Example output

```json
{
  "total_lines": 3,
  "categorized_lines": {
    "ru_or_ua": 1,
    "latin_only": 1,
    "mixed": 1,
    "unknown": 0
  },
  "suspicious_keyword_hits": {
    "admin": 1,
    "password": 1,
    "админ": 1
  }
}
```
## Real-world usage

## Real-world testing

This tool has been tested against real-world Nginx access logs from a publicly exposed server.

The logs include:
- automated scanning traffic
- brute-force login attempts
- common probing patterns (e.g. `/admin`, `/login`, `/passwd`)

The analysis works with:
- standard Latin-based attack patterns
- URL-encoded paths
- multilingual payloads (e.g. Cyrillic) when present

- Nginx access logs
- SSH authentication logs
- Self-hosted environments

Example use cases:
- detecting brute-force login attempts
- identifying non-Latin attack patterns
- analyzing suspicious traffic sources

# Future ideas

## Version 2
- IP-based aggregation
- endpoint clustering
- request method statistics
- suspicious path detection
- user-agent anomaly detection

## Security integrations
- Fail2ban filter helper output
- blocklist generation
- cron-compatible reporting

## Language analysis improvements
- better RU vs UA differentiation
- transliterated keyword detection
- phrase scoring
- mixed-language payload analysis
