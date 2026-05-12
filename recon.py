"""
recon.py — Part 4: Integrated Reconnaissance Tool
Performs multi-stage active reconnaissance on a domain or IP address.
"""

import argparse
import json
import logging
import re
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


def is_ip(target: str) -> bool:
    """Return True if target looks like an IPv4 address."""
    try:
        socket.inet_aton(target)
        return True
    except OSError:
        return False


def require_tool(name: str) -> bool:
    """Warn if an external tool is not on PATH."""
    if shutil.which(name) is None:
        logging.warning("Tool not found on PATH: %s — skipping related steps", name)
        return False
    return True


def run(cmd: list[str], timeout: int = 30) -> tuple[bool, str]:
    """
    Run a subprocess command.
    Returns (success: bool, output: str).
    Logs the command and outcome; never raises.
    """
    logging.info("RUN: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout.strip() or result.stderr.strip()
        if result.returncode == 0:
            logging.info("OK (%d bytes)", len(output))
        else:
            logging.warning("exit %d: %s", result.returncode, output[:200])
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        logging.warning("TIMEOUT after %ds: %s", timeout, " ".join(cmd))
        return False, f"[timeout after {timeout}s]"
    except Exception as exc:
        logging.error("ERROR: %s — %s", " ".join(cmd), exc)
        return False, f"[error: {exc}]"



def step_whois_domain(domain: str) -> dict:
    ok, raw = run(["whois", domain], timeout=20)
    if not ok:
        return {"error": raw}

    def extract(pattern: str) -> str | None:
        m = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else None

    return {
        "registrar":          extract(r"Registrar:\s*(.+)"),
        "registration_date":  extract(r"Creation Date:\s*(.+)"),
        "expiry_date":        extract(r"Registrar Registration Expiration Date:\s*(.+)")
                              or extract(r"Registry Expiry Date:\s*(.+)"),
        "registrant_org":     extract(r"Registrant Organization:\s*(.+)"),
    }


def step_dns(domain: str) -> dict:
    records: dict[str, list[str]] = {}
    for rtype in ("A", "MX", "NS", "TXT"):
        ok, out = run(["dig", "+short", domain, rtype], timeout=10)
        records[rtype] = [l for l in out.splitlines() if l] if ok else []
    return records


def step_http_headers(domain: str) -> dict:
    ok, raw = run(["curl", "-sI", "--max-time", "10", f"http://{domain}"], timeout=15)
    if not ok:
        return {"error": raw}

    headers: dict[str, str] = {}
    for line in raw.splitlines()[1:]:        # skip status line
        if ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()

    interesting = ["server", "x-powered-by", "content-security-policy",
                   "strict-transport-security", "x-frame-options",
                   "x-content-type-options"]
    return {k: headers[k] for k in interesting if k in headers}

def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parse nmap XML output and return a list of port dicts."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logging.error("nmap XML parse error: %s", exc)
        return []

    ports = []
    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            ports.append({
                "port":    int(port.get("portid")),
                "service": svc.get("name")    if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
            })
    return ports


def step_nmap_ip(ip: str) -> dict:
    ok, xml = run(
        ["nmap", "-sV", "--open", "--top-ports", "100", "-oX", "-", ip],
        timeout=120,
    )
    if not ok:
        return {"error": xml}
    return {"open_ports": parse_nmap_xml(xml)}


def step_rdns(ip: str) -> dict:
    ok, out = run(["dig", "+short", "-x", ip], timeout=10)
    return {"hostname": out.splitlines()[0].rstrip(".") if ok and out else None}


def step_whois_ip(ip: str) -> dict:
    ok, raw = run(["whois", ip], timeout=20)
    if not ok:
        return {"error": raw}

    def extract(pattern: str) -> str | None:
        m = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else None

    return {
        "organization": extract(r"(?:OrgName|org-name|netname):\s*(.+)"),
        "country":      extract(r"(?:Country|country):\s*(.+)"),
    }

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
]


def generate_markdown(target: str, mode: str, results: dict) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# Recon Report: `{target}`",
        f"\n_Mode: **{mode}** — Generated: {now}_\n",
        "---\n",
    ]

    # Summary table
    lines += [
        "## Summary\n",
        "| Field | Value |",
        "|---|---|",
        f"| Target | {target} |",
        f"| Mode | {mode} |",
        f"| Timestamp | {now} |",
    ]

    if mode == "ip":
        nmap = results.get("nmap", {})
        open_ports = nmap.get("open_ports", [])
        lines.append(f"| Open Ports | {len(open_ports)} |")

        rdns = results.get("rdns", {}).get("hostname")
        lines.append(f"| Reverse DNS | {rdns or 'N/A'} |")

        whois_ip = results.get("whois_ip", {})
        lines.append(f"| Organization | {whois_ip.get('organization', 'N/A')} |")
        lines.append(f"| Country | {whois_ip.get('country', 'N/A')} |")

        lines += [
            "\n## Open Ports\n",
            "| Port | Service | Version |",
            "|---|---|---|",
        ]
        if open_ports:
            for p in open_ports:
                lines.append(
                    f"| {p['port']} | {p['service'] or '?'} | {p['version'] or '?'} |"
                )
        else:
            lines.append("| — | No open ports found | |")

    else: 
        dns = results.get("dns", {})
        a_records = ", ".join(dns.get("A", [])) or "N/A"
        lines.append(f"| A Records | {a_records} |")

        whois_d = results.get("whois_domain", {})
        lines.append(f"| Registrar | {whois_d.get('registrar', 'N/A')} |")
        lines.append(f"| Expires | {whois_d.get('expiry_date', 'N/A')} |")

        lines += ["\n## DNS Records\n"]
        for rtype, vals in dns.items():
            lines.append(f"### {rtype}\n")
            if vals:
                for v in vals:
                    lines.append(f"- `{v}`")
            else:
                lines.append("_None_")
            lines.append("")

        headers = results.get("http_headers", {})
        lines += ["\n## HTTP Response Headers\n"]
        if "error" in headers:
            lines.append(f"_Error fetching headers: {headers['error']}_")
        else:
            if headers:
                lines += ["| Header | Value |", "|---|---|"]
                for k, v in headers.items():
                    lines.append(f"| `{k}` | {v} |")
            else:
                lines.append("_No headers captured._")

            missing = [h for h in SECURITY_HEADERS if h not in headers]
            if missing:
                lines += [
                    "\n### ⚠️ Missing Security Headers\n",
                    "The following security headers were **not present** in the response:\n",
                ]
                for h in missing:
                    lines.append(f"- `{h}`")

        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Integrated reconnaissance tool — domain and IP modes"
    )
    parser.add_argument("target",   help="Domain name or IP address")
    parser.add_argument("--mode",   choices=["domain", "ip"],
                        help="Force mode; auto-detected if omitted")
    parser.add_argument("--output", default=None,
                        help="Output directory (default: ./recon_<target>_<ts>/)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print progress to stderr")
    args = parser.parse_args()

    target = args.target
    mode   = args.mode or ("ip" if is_ip(target) else "domain")

    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r"[^\w.\-]", "_", target)
    out_dir   = Path(args.output) if args.output else Path(f"recon_{safe_name}_{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    handlers: list[logging.Handler] = [
        logging.FileHandler(out_dir / "audit.log")
    ]
    if args.verbose:
        handlers.append(logging.StreamHandler(sys.stderr))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers,
    )

    logging.info("=== recon.py start — target=%s mode=%s ===", target, mode)

    results: dict = {}

    if mode == "domain":
        if require_tool("whois"):
            logging.info("STEP: whois (domain)")
            results["whois_domain"] = step_whois_domain(target)

        if require_tool("dig"):
            logging.info("STEP: DNS records")
            results["dns"] = step_dns(target)

        if require_tool("curl"):
            logging.info("STEP: HTTP headers")
            results["http_headers"] = step_http_headers(target)

    else:
        if require_tool("nmap"):
            logging.info("STEP: nmap -sV --top-ports 100")
            results["nmap"] = step_nmap_ip(target)

        if require_tool("dig"):
            logging.info("STEP: reverse DNS")
            results["rdns"] = step_rdns(target)

        if require_tool("whois"):
            logging.info("STEP: whois (IP)")
            results["whois_ip"] = step_whois_ip(target)

    results_path = out_dir / "results.json"
    results_path.write_text(json.dumps(results, indent=2))
    logging.info("WRITE results.json (%d bytes)", results_path.stat().st_size)

    report_md   = generate_markdown(target, mode, results)
    report_path = out_dir / "report.md"
    report_path.write_text(report_md)
    logging.info("WRITE report.md (%d bytes)", report_path.stat().st_size)

    logging.info("=== recon.py done — output dir: %s ===", out_dir)

    print(f"[+] Done. Results in: {out_dir}/")
    print(f"    results.json  : {results_path}")
    print(f"    report.md     : {report_path}")
    print(f"    audit.log     : {out_dir / 'audit.log'}")


if __name__ == "__main__":
    main()
