"""
auth_analysis.py
Analyzes SSH authentication logs to detect brute-force attempts.
"""

import re
import argparse
from collections import defaultdict, Counter
from pathlib import Path


AUTH_FAIL = re.compile(r"Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)")
AUTH_OK   = re.compile(r"Accepted \S+ for (\S+) from (\d+\.\d+\.\d+\.\d+)")


def analyze_auth_log(log_path: str, threshold: int = 10) -> dict:
    failed_by_ip: dict[str, int]   = defaultdict(int)
    targeted_users: Counter        = Counter()
    success_by_ip: dict[str, int]  = defaultdict(int)
    total_failures = 0
    total_successes = 0

    for line in Path(log_path).open(errors="replace"):
        m_fail = AUTH_FAIL.search(line)
        if m_fail:
            user, ip = m_fail.group(1), m_fail.group(2)
            failed_by_ip[ip] += 1
            targeted_users[user] += 1
            total_failures += 1
            continue

        m_ok = AUTH_OK.search(line)
        if m_ok:
            success_by_ip[m_ok.group(2)] += 1
            total_successes += 1

    brute_force_ips = sorted(
        [(ip, cnt) for ip, cnt in failed_by_ip.items() if cnt >= threshold],
        key=lambda x: x[1],
        reverse=True,
    )

    ratio = (
        round(total_failures / total_successes, 2)
        if total_successes > 0
        else float("inf")
    )

    return {
        "brute_force_ips": brute_force_ips,
        "targeted_users": targeted_users.most_common(),
        "total_failures": total_failures,
        "total_successes": total_successes,
        "fail_to_success_ratio": ratio,
    }


def print_report(results: dict) -> None:
    print("\n" + "=" * 55)
    print("  AUTH LOG ANALYSIS REPORT")
    print("=" * 55)

    print(f"\n[+] Total failed logins  : {results['total_failures']}")
    print(f"[+] Total successful     : {results['total_successes']}")
    ratio = results["fail_to_success_ratio"]
    ratio_str = f"{ratio:.2f}" if ratio != float("inf") else "∞ (no successes)"
    print(f"[+] Fail / success ratio : {ratio_str}")

    print("\n--- IPs with > threshold failed attempts (brute-force) ---")
    if results["brute_force_ips"]:
        for ip, cnt in results["brute_force_ips"]:
            print(f"  {ip:<20} {cnt} attempts")
    else:
        print("  None found.")

    print("\n--- Targeted usernames ---")
    for user, cnt in results["targeted_users"]:
        print(f"  {user:<20} {cnt} attempts")

    print("=" * 55 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="SSH auth log analyzer — detects brute-force attempts"
    )
    parser.add_argument("--input",     required=True, help="Path to auth.log")
    parser.add_argument("--threshold", type=int, default=10,
                        help="Min failed attempts to flag an IP (default: 10)")
    args = parser.parse_args()

    results = analyze_auth_log(args.input, args.threshold)
    print_report(results)
    return results 


if __name__ == "__main__":
    main()
