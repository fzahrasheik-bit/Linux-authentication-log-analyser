#!/usr/bin/env python3
"""Analyse Linux authentication logs for repeated failed SSH logins."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import ipaddress
import json
from pathlib import Path
import re

# Matches common OpenSSH messages such as:
# Failed password for invalid user admin from 203.0.113.10 port 4422 ssh2
FAILED_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+) port \d+"),
    re.compile(r"Invalid user (\S+) from ([0-9a-fA-F:.]+)"),
    re.compile(r"authentication failure;.*?rhost=([0-9a-fA-F:.]+).*?user=(\S+)")
]

def extract_failed_attempt(line: str):
    """Return (username, IP) for a recognised failed-authentication line."""
    match = FAILED_PATTERNS[0].search(line)
    if match:
        return match.group(1), match.group(2)
    match = FAILED_PATTERNS[1].search(line)
    if match:
        return match.group(1), match.group(2)
    match = FAILED_PATTERNS[2].search(line)
    if match:
        return match.group(2), match.group(1)
    return None

def analyse_log(log_path: Path, threshold: int = 5):
    """Parse a log and return summary data. Threshold is attempts per source IP."""
    attempts_by_ip = Counter()
    users_by_ip = defaultdict(Counter)
    matched_lines = []
    total_lines = 0

    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            total_lines += 1
            result = extract_failed_attempt(line)
            if not result:
                continue
            username, ip = result
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            attempts_by_ip[ip] += 1
            users_by_ip[ip][username] += 1
            matched_lines.append({"line": line_number, "username": username, "ip": ip})

    flagged = []
    for ip, count in attempts_by_ip.most_common():
        if count >= threshold:
            flagged.append({
                "ip": ip,
                "failed_attempts": count,
                "usernames_targeted": sorted(users_by_ip[ip]),
                "classification": "threshold_exceeded"
            })

    return {
        "source_file": str(log_path),
        "total_lines": total_lines,
        "failed_attempts": sum(attempts_by_ip.values()),
        "unique_source_ips": len(attempts_by_ip),
        "threshold": threshold,
        "flagged_ips": flagged,
        "attempts_by_ip": dict(attempts_by_ip.most_common()),
        "matched_events": matched_lines
    }

def make_markdown_report(data: dict) -> str:
    lines = [
        "# Linux Authentication Log Analysis",
        "",
        f"- **Source:** `{data['source_file']}`",
        f"- **Log lines scanned:** {data['total_lines']}",
        f"- **Failed login events:** {data['failed_attempts']}",
        f"- **Unique source IPs:** {data['unique_source_ips']}",
        f"- **Alert threshold:** {data['threshold']} failed attempts per IP",
        "",
        "## Flagged IP addresses",
        "",
    ]
    if data["flagged_ips"]:
        lines += ["| Source IP | Failed attempts | Usernames targeted |",
                  "|---|---:|---|"]
        for item in data["flagged_ips"]:
            lines.append(
                f"| `{item['ip']}` | {item['failed_attempts']} | "
                f"{', '.join(item['usernames_targeted'])} |"
            )
    else:
        lines.append("No IP addresses reached the configured threshold.")
    lines += [
        "",
        "## Interpretation",
        "",
        "An IP is flagged because its failed-login count reached the configured "
        "threshold. This is a triage signal, not proof that the IP is malicious. "
        "Investigate the surrounding events and validate the source before taking action.",
        "",
        "## Method",
        "",
        "The analyser scans each line for common OpenSSH failed-password and invalid-user "
        "messages, validates extracted IP addresses, counts events by source IP, and "
        "flags sources at or above the threshold.",
        ""
    ]
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(
        description="Find repeated failed SSH login attempts in Linux auth logs."
    )
    parser.add_argument("logfile", nargs="?", default="sample_logs/auth.log",
                        help="Path to auth.log (default: sample_logs/auth.log)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts from one IP needed to flag it (default: 5)")
    parser.add_argument("--out", default="reports",
                        help="Directory for Markdown and JSON reports (default: reports)")
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    path = Path(args.logfile)
    if not path.is_file():
        parser.error(f"log file not found: {path}")

    data = analyse_log(path, args.threshold)
    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "security_report.md").write_text(
        make_markdown_report(data), encoding="utf-8"
    )
    (output_dir / "security_report.json").write_text(
        json.dumps(data, indent=2), encoding="utf-8"
    )

    print("\n=== LINUX AUTH LOG ANALYSER ===")
    print(f"Lines scanned       : {data['total_lines']}")
    print(f"Failed logins       : {data['failed_attempts']}")
    print(f"Unique source IPs   : {data['unique_source_ips']}")
    print(f"Flagged IPs         : {len(data['flagged_ips'])}")
    for item in data["flagged_ips"]:
        print(f"  [ALERT] {item['ip']} - {item['failed_attempts']} failed attempts")
    print(f"\nReports saved in: {output_dir.resolve()}")
    print("Note: a flagged IP requires investigation; it is not automatically malicious.")

if __name__ == "__main__":
    main()
