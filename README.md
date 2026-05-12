# Security Scripting Lab15 SPTI

- Yojhan Toro 
- Ivan Cubillos 

## Requirements

- Python 3.10+
- External tools: nmap, whois, dig, curl, ssh-keyscan

```bash
pip install python-dotenv
```

Everything else uses only the standard library: re, statistics, collections, subprocess, xml.etree.ElementTree, argparse, logging, socket.

---

## Part 3 — Log Analysis and Anomaly Detection

### auth_analysis.py

This script reads an SSH auth log and figures out which IPs are hammering the server with failed login attempts, which usernames they're targeting, and what the overall ratio of failed to successful logins looks like.

```bash
python3 auth_analysis.py --input /var/log/auth.log --threshold 10
```

| Flag | Description | Default |
|---|---|---|
| --input | Path to the auth log | required |
| --threshold | Min failed attempts to flag an IP | 10 |

The log is read line by line so it never loads the whole file into memory, which matters when you're dealing with multi-gigabyte logs from a busy server. Two regex patterns handle the matching: one for failed logins, one for successful ones. All the counting happens with defaultdict and Counter so the code stays clean without a bunch of explicit key checks.

One design decision worth mentioning: analyze_auth_log returns a plain dict instead of just printing things. That way log_analysis.py can import it and reuse the results without re-parsing the file a second time.

---

### log_analysis.py

This one handles web access logs. It looks for attack patterns in request paths, summarizes traffic by IP and HTTP status code, and runs a 3-sigma anomaly detector on hourly request counts to catch traffic spikes. At the end it writes everything to a Markdown report. If you also pass an auth log it will pull in those results too and combine them into a single report.

```bash
# just the access log
python3 log_analysis.py --access access.log --report report.md

# with auth log and a tighter sigma threshold
python3 log_analysis.py --access access.log --auth auth.log --report report.md --sigma 2.5
```

| Flag | Description | Default |
|---|---|---|
| --access | Path to the web access log | required |
| --auth | Path to auth.log, optional | None |
| --report | Output Markdown file | report.md |
| --sigma | Z-score threshold for anomaly detection | 3.0 |

The attack detection covers SQL injection, path traversal, XSS, command injection, and common scanner paths like /wp-admin/ or /.env. All the regex patterns are compiled once at module level rather than inside the loop, which makes a real difference when you're processing millions of lines.

The anomaly detector uses sample standard deviation rather than population standard deviation, which is the right choice when the log covers a slice of time rather than a complete dataset. The --sigma flag is configurable because a low-traffic server might need 2.5 to catch anything interesting, while a noisy one might need 4 to avoid false positives.

The report generator is written as a pure function that takes data as arguments and does not touch any files itself. That makes it easier to test in isolation and reuse if you ever want to call it from somewhere else.

---

## Part 4 — Integrated Reconnaissance Tool

### recon.py

A single-file recon tool that runs multiple information-gathering steps against a domain or IP and saves everything to a structured output directory. It produces three files: results.json with all the findings, report.md with a readable summary, and audit.log with a timestamped record of every action the tool took.

```bash
# domain mode (auto-detected)
python3 recon.py example.com --verbose

# IP mode
python3 recon.py 192.168.1.10 --output ./recon_output/ --verbose

# forcing a mode explicitly
python3 recon.py example.com --mode domain --output ./out/
```

| Flag | Description | Default |
|---|---|---|
| target | Domain name or IP address | required |
| --mode | domain or ip, auto-detected if omitted | auto |
| --output | Output directory | ./recon_target_timestamp/ |
| --verbose | Also print progress to stderr | off |

In domain mode it runs whois to get registrar and expiry info, dig to pull A, MX, NS, and TXT records, and curl -I to grab HTTP response headers. It also checks which security headers are missing from the response (CSP, HSTS, X-Frame-Options, X-Content-Type-Options). In IP mode it runs nmap with service version detection, does a reverse DNS lookup with dig, and runs whois on the IP to get the owning organization and country.

Every external command goes through a single run() helper. That function handles the subprocess call, enforces a timeout, logs the command and result to audit.log, and returns a success/output pair instead of raising exceptions. The point is that if one step times out or fails, the rest still run. You do not lose your nmap results because whois decided to hang.

A few other decisions that were made deliberately: the output directory is timestamped by default so re-running the tool never overwrites previous results. The audit log is always written regardless of whether --verbose is on, because in a real engagement you need that record even if nobody was watching the terminal. And results.json contains parsed structured data rather than raw tool output, so it is actually useful if you want to feed it into another script later.
