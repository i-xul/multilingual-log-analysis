#!/usr/bin/env python3

import argparse
import json
import os
import re
from collections import Counter
from typing import Dict, List


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


def analyze_lines(lines: List[str]) -> Dict:
    categorized_counter = Counter()
    keyword_counter = Counter()
    ip_counter = Counter()
    suspicious_lines = []
    ip_stats = {}

    for line in lines:
        category = detect_language_category(line)
        categorized_counter[category] += 1

        ip = extract_ip(line)
        ip_counter[ip] += 1

        if ip not in ip_stats:
            ip_stats[ip] = {
                "requests": 0,
                "suspicious_hits": 0,
            }

        ip_stats[ip]["requests"] += 1

        keyword_hits = find_suspicious_keywords(line)

        if keyword_hits:
            keyword_counter.update(keyword_hits)
            ip_stats[ip]["suspicious_hits"] += 1

            suspicious_lines.append({
                "ip": ip,
                "category": category,
                "keywords": keyword_hits,
                "line": line,
            })

    # Build IP scores
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
        "suspicious_keyword_hits": dict(keyword_counter.most_common()),
        "ip_scores": ip_scores,
        "suspicious_lines": suspicious_lines,
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
        "suspicious_keyword_hits": dict(keyword_counter.most_common()),
        "ip_scores": ip_scores,
        "suspicious_lines": suspicious_lines,
    }
            )

    return {
        "total_lines": len(lines),
        "categorized_lines": {
            "ru_or_ua": categorized_counter.get("ru_or_ua", 0),
            "latin_only": categorized_counter.get("latin_only", 0),
            "mixed": categorized_counter.get("mixed", 0),
            "unknown": categorized_counter.get("unknown", 0),
        },
        "top_source_ips": dict(ip_counter.most_common(10)),
        "suspicious_keyword_hits": dict(keyword_counter.most_common()),
        "ip_scores": ip_scores,
        "top_paths": dict(path_counter.most_common(10)),
        "suspicious_lines": suspicious_lines,
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

    print("\nSuspicious keywords:")
    if report["suspicious_keyword_hits"]:
        for keyword, count in report["suspicious_keyword_hits"].items():
            print(f"  {keyword}: {count}")
    else:
        print("  No suspicious keywords found.")

    print(f"\nSuspicious lines stored: {len(report['suspicious_lines'])}")


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
