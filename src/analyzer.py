#!/usr/bin/env python3

import argparse
import json
import os
import re
from collections import Counter
from typing import Dict, List
from urllib.parse import unquote


CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")
LATIN_RE = re.compile(r"[A-Za-z]")

# Simple keyword sets for an initial heuristic version
SUSPICIOUS_KEYWORDS = [
    "admin",
    "root",
    "password",
    "login",
    "wp-login",
    "phpmyadmin",
    "shell",
    "passwd",
    "админ",
    "пароль",
    "логин",
    "вход",
    "обліковий",
    "користувач",
]


def load_lines(file_path: str) -> List[str]:
    """Read all lines from a log file using a tolerant UTF-8 strategy."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as file:
        return [line.rstrip("\n") for line in file]


def detect_language_category(text: str) -> str:
    """
    Very simple character-based categorization.

    Returns:
        - ru_or_ua: contains Cyrillic but no Latin
        - latin_only: contains Latin but no Cyrillic
        - mixed: contains both Cyrillic and Latin
        - unknown: contains neither
    """
    has_cyrillic = bool(CYRILLIC_RE.search(text))
    has_latin = bool(LATIN_RE.search(text))

    if has_cyrillic and has_latin:
        return "mixed"
    if has_cyrillic:
        return "ru_or_ua"
    if has_latin:
        return "latin_only"
    return "unknown"


def find_suspicious_keywords(text: str) -> List[str]:
    """Return suspicious keywords found in the text."""
    lowered = text.lower()
    hits = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in lowered:
            hits.append(keyword)

    return hits


def extract_ip(text: str) -> str:
    """
    Try to extract an IPv4 address from a log line.
    Returns 'unknown' if no IP is found.
    """
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return match.group(0) if match else "unknown"
    
def extract_path(text: str) -> str:
    """
    Try to extract the request path from a typical Nginx access log line.

    Supports:
    - normal requests like: "GET /admin HTTP/1.1"
    - special requests like: "OPTIONS * HTTP/1.0"

    Returns 'unknown' if no usable path is found.
    """
    request_match = re.search(r'"([^"]+)"', text)
    if not request_match:
        return "unknown"

    request = request_match.group(1).strip()
    parts = request.split()

    if len(parts) < 2:
        return "unknown"

    method = parts[0]
    target = parts[1]

    valid_methods = {
        "GET", "POST", "HEAD", "PUT", "DELETE",
        "OPTIONS", "PATCH", "CONNECT", "TRACE"
    }

    if method not in valid_methods:
        return "unknown"

    return target

def analyze_lines(lines: List[str]) -> Dict:
    unknown_path_lines = []
    categorized_counter = Counter()
    keyword_counter = Counter()
    ip_counter = Counter()
    path_counter = Counter()
    suspicious_lines = []
    ip_stats = {}

    for line in lines:
        decoded_line = unquote(line)

        category = detect_language_category(decoded_line)
        categorized_counter[category] += 1

        ip = extract_ip(decoded_line)
        ip_counter[ip] += 1

        path = extract_path(decoded_line)
        path_counter[path] += 1
        if path == "unknown" and len(unknown_path_lines) < 10:
        unknown_path_lines.append(line)

        if ip not in ip_stats:
            ip_stats[ip] = {
                "requests": 0,
                "suspicious_hits": 0,
            }

        ip_stats[ip]["requests"] += 1

        keyword_hits = find_suspicious_keywords(decoded_line)

        if keyword_hits:
            keyword_counter.update(keyword_hits)
            ip_stats[ip]["suspicious_hits"] += 1

            suspicious_lines.append({
                "ip": ip,
                "path": path,
                "category": category,
                "keywords": keyword_hits,
                "line": line,
            })

    ip_scores = {}

    for ip, stats in ip_stats.items():
        requests = stats["requests"]
        suspicious_hits = stats["suspicious_hits"]
        score = suspicious_hits / requests if requests else 0.0

        ip_scores[ip] = {
            "requests": requests,
            "suspicious_hits": suspicious_hits,
            "score": round(score, 2),
        }

    return {
        "total_lines": len(lines),
        "categorized_lines": {
            "ru_or_ua": categorized_counter.get("ru_or_ua", 0),
            "latin_only": categorized_counter.get("latin_only", 0),
            "mixed": categorized_counter.get("mixed", 0),
            "unknown": categorized_counter.get("unknown", 0),
        },
        "top_source_ips": dict(ip_counter.most_common(10)),
        "top_paths": dict(path_counter.most_common(10)),
        "suspicious_keyword_hits": dict(keyword_counter.most_common()),
        "ip_scores": ip_scores,
        "suspicious_lines": suspicious_lines,
        "unknown_path_examples": unknown_path_lines,
    }


def save_json(data: Dict, output_path: str) -> None:
    """Write analysis result into a JSON file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def print_summary(report: Dict) -> None:
    """Print a clean CLI summary for quick analysis."""

    print("\n=== Multilingual Log Analysis Summary ===")
    print(f"\nTotal lines: {report['total_lines']}")

    print("\nCategories:")
    for key, value in report["categorized_lines"].items():
        print(f"  {key}: {value}")

    print("\nTop source IPs:")
    if report["top_source_ips"]:
        for ip, count in report["top_source_ips"].items():
            print(f"  {ip}: {count}")
    else:
        print("  No IPs detected.")

    print("\nTop paths:")
    if report.get("top_paths"):
        for path, count in report["top_paths"].items():
            print(f"  {path}: {count}")
    else:
        print("  No paths detected.")

    print("\nSuspicious keywords:")
    if report["suspicious_keyword_hits"]:
        for keyword, count in report["suspicious_keyword_hits"].items():
            print(f"  {keyword}: {count}")
    else:
        print("  No suspicious keywords found.")

    print("\nTop suspicious IP scores:")
    if report.get("ip_scores"):
        sorted_scores = sorted(
            report["ip_scores"].items(),
            key=lambda item: item[1]["score"],
            reverse=True,
        )[:10]

        for ip, data in sorted_scores:
            print(
                f"  {ip}: score={data['score']} "
                f"(requests={data['requests']}, suspicious_hits={data['suspicious_hits']})"
            )
    else:
        print("  No IP scores available.")

    print(f"\nSuspicious lines stored: {len(report['suspicious_lines'])}")

    print("\nUnknown path examples:")
    if report.get("unknown_path_examples"):
        for line in report["unknown_path_examples"]:
            print(f"  {line}")
    else:
        print("  No unknown path examples.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze log files for multilingual and suspicious attack patterns."
    )
    parser.add_argument(
        "logfile",
        help="Path to the log file to analyze.",
    )
    parser.add_argument(
        "--output",
        default="output/report.json",
        help="Path to save the JSON report. Default: output/report.json",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not os.path.exists(args.logfile):
        raise FileNotFoundError(f"Log file not found: {args.logfile}")

    lines = load_lines(args.logfile)
    report = analyze_lines(lines)
    save_json(report, args.output)
    print_summary(report)

    print(f"\nJSON report written to: {args.output}")


if __name__ == "__main__":
    main()
