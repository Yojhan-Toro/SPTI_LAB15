"""
log_analysis.py — Part 3 C/D/E
Analyzes Apache-style access logs for attack patterns and traffic anomalies.
Also calls auth_analysis to produce a combined report.md.

Usage:
    python3 log_analysis.py --access access.log [--auth auth.log] [--report report.md]
"""

import re
import statistics
import argparse
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# ── Regex patterns ────────────────────────────────────────────────────────────

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\S+)'
)

# Hour extracted from Combined Log Format timestamp
HOUR_PATTERN = re.compile(r'\d{2}/\w+/\d{4}:(\d{2}):\d{2}:\d{2}')

ATTACK_PATTERNS = re.compile(
    # SQL injection
    r"(union.*select|insert\s+into|drop\s+table|select.*from"
    r"|or\s+1\s*=\s*1|'--|\bor\b.*=.*--)"
    # Path traversal
    r"|(\.\.\/|\.\.\\)"
    # XSS
    r"|(<script|javascript:|onerror\s*=|onload\s*=)"
    # Command injection
    r"|(cmd=|exec=|shell=|;.*\bcat\b|;.*\bls\b|\|.*\bwhoami\b)"
    # Sensitive file access
    r"|(\/etc\/passwd|\/etc\/shadow|\/proc\/self)"
    # Common scanner paths
    r"|(\/wp-admin\/|\/\.env|\/\.git\/|\/phpmyadmin)",
    re.IGNORECASE,
)


# ── Core analysis functions ───────────────────────────────────────────────────

def analyze_access_log(log_path: str) -> dict:
    ip_counts:      Counter = Counter()
    status_counts:  Counter = Counter()
    hourly_counts:  dict[str, int] = defaultdict(int)
    suspicious:     list[dict]     = []

    for line in Path(log_path).open(errors="replace"):
        m = LOG_PATTERN.match(line)
        if not m:
            continue

        ip     = m.group("ip")
        status = m.group("status")
        path   = m.group("path")
        ts_raw = m.group("ts")

        ip_counts[ip] += 1
        status_counts[status] += 1

        # Extract hour for anomaly detection
        hm = HOUR_PATTERN.search(ts_raw)
        if hm:
            hourly_counts[hm.group(1)] += 1

        if ATTACK_PATTERNS.search(path):
            suspicious.append({
                "ip":     ip,
                "path":   path,
                "status": status,
            })

    return {
        "top_ips":              ip_counts.most_common(5),
        "status_distribution":  dict(status_counts),
        "suspicious_requests":  suspicious,
        "hourly_counts":        dict(hourly_counts),
    }


def detect_traffic_anomalies(hourly_counts: dict[str, int],
                              sigma_threshold: float = 3.0) -> list[str]:
    if len(hourly_counts) < 2:
        return []

    counts = list(hourly_counts.values())
    mean   = statistics.mean(counts)
    stdev  = statistics.stdev(counts)

    if stdev == 0:
        return []

    threshold = mean + sigma_threshold * stdev
    anomalies = []

    for hour, count in sorted(hourly_counts.items()):
        if count > threshold:
            z = (count - mean) / stdev
            anomalies.append(
                f"[ANOMALY] {hour}:00 — {count} requests "
                f"(z={z:.1f}σ, threshold={sigma_threshold:.1f}σ)"
            )
    return anomalies


# ── Combined report generator ─────────────────────────────────────────────────

def generate_report(
    access_results: dict,
    anomalies: list[str],
    auth_results: dict | None,
    output_path: str,
) -> None:
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines += [
        "# Security Log Analysis Report",
        f"\n_Generated: {now}_\n",
        "---\n",
    ]

    # ── Section 1: Suspicious web requests ──────────────────────────────────
    lines += [
        "## 1. Suspicious Web Requests\n",
        f"Detected **{len(access_results['suspicious_requests'])}** potentially malicious requests.\n",
    ]
    if access_results["suspicious_requests"]:
        lines.append("| IP | Path | Status |")
        lines.append("|---|---|---|")
        for req in access_results["suspicious_requests"]:
            # Escape pipe characters inside paths
            safe_path = req['path'].replace("|", "\\|")
            lines.append(f"| {req['ip']} | `{safe_path}` | {req['status']} |")
    else:
        lines.append("_No suspicious requests found._")
    lines.append("")

    # ── Section 2: Top IPs ───────────────────────────────────────────────────
    lines += [
        "## 2. Top 5 IPs by Request Volume\n",
        "| Rank | IP Address | Requests |",
        "|---|---|---|",
    ]
    for rank, (ip, cnt) in enumerate(access_results["top_ips"], 1):
        lines.append(f"| {rank} | {ip} | {cnt} |")
    lines.append("")

    # ── Section 3: HTTP status distribution ─────────────────────────────────
    lines += [
        "## 3. HTTP Status Code Distribution\n",
        "| Status | Count |",
        "|---|---|",
    ]
    for status, cnt in sorted(access_results["status_distribution"].items()):
        lines.append(f"| {status} | {cnt} |")
    lines.append("")

    # ── Section 4: Traffic anomalies ─────────────────────────────────────────
    lines += ["## 4. Traffic Anomaly Detection (3σ rule)\n"]
    if anomalies:
        for a in anomalies:
            lines.append(f"- {a}")
    else:
        lines.append("_No anomalous hours detected._")
    lines.append("")

    # ── Section 5: Auth log (optional) ───────────────────────────────────────
    if auth_results:
        lines += [
            "## 5. SSH Authentication Analysis\n",
            f"- **Total failed logins:** {auth_results['total_failures']}",
            f"- **Total successful logins:** {auth_results['total_successes']}",
            f"- **Fail/success ratio:** {auth_results['fail_to_success_ratio']}\n",
            "### Brute-force IPs (>10 failures)\n",
            "| IP | Failed Attempts |",
            "|---|---|",
        ]
        if auth_results["brute_force_ips"]:
            for ip, cnt in auth_results["brute_force_ips"]:
                lines.append(f"| {ip} | {cnt} |")
        else:
            lines.append("| — | No IPs exceeded threshold |")

        lines += [
            "",
            "### Targeted Usernames\n",
            "| Username | Attempts |",
            "|---|---|",
        ]
        for user, cnt in auth_results["targeted_users"]:
            lines.append(f"| {user} | {cnt} |")
        lines.append("")

    Path(output_path).write_text("\n".join(lines))
    print(f"[+] Report written to {output_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Web access log analyzer with anomaly detection"
    )
    parser.add_argument("--access", required=True, help="Path to access.log")
    parser.add_argument("--auth",   default=None,  help="Path to auth.log (optional)")
    parser.add_argument("--report", default="report.md", help="Output markdown report")
    parser.add_argument("--sigma",  type=float, default=3.0,
                        help="Z-score threshold for anomaly detection (default: 3.0)")
    args = parser.parse_args()

    print(f"[*] Analyzing access log: {args.access}")
    access_results = analyze_access_log(args.access)
    anomalies      = detect_traffic_anomalies(access_results["hourly_counts"], args.sigma)

    # Print findings to stdout
    print(f"\n[+] Suspicious requests : {len(access_results['suspicious_requests'])}")
    print(f"[+] Top 5 IPs           :")
    for ip, cnt in access_results["top_ips"]:
        print(f"      {ip:<20} {cnt} requests")

    print(f"\n[+] Status distribution :")
    for status, cnt in sorted(access_results["status_distribution"].items()):
        print(f"      HTTP {status}: {cnt}")

    print(f"\n[+] Traffic anomalies   :")
    if anomalies:
        for a in anomalies:
            print(f"      {a}")
    else:
        print("      None detected.")

    # Auth log (optional)
    auth_results = None
    if args.auth:
        from auth_analysis import analyze_auth_log, print_report
        print(f"\n[*] Analyzing auth log: {args.auth}")
        auth_results = analyze_auth_log(args.auth)
        print_report(auth_results)

    # Combined markdown report
    generate_report(access_results, anomalies, auth_results, args.report)


if __name__ == "__main__":
    main()
