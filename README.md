# Multilingual Log Analysis

A Python-based security log analysis project for identifying language-related attack patterns in server logs.

This project focuses on:
- detecting suspicious requests in web server and authentication logs
- identifying Cyrillic and multilingual attack attempts
- extracting keywords often seen in brute-force or probing activity
- producing simple JSON reports for further analysis

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

## Current status

Initial working prototype.

## Usage

```bash
python3 src/analyzer.py sample_logs/nginx_access_sample.log
