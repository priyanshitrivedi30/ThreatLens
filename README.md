# ThreatLens 🛡️
### SSH Honeypot Analyzer — CLI Security Tool

A professional Python CLI tool that deploys a fake SSH server to capture and analyze real-world brute-force attacks. Built for cybersecurity portfolios and SOC analyst skill demonstration.

---

## What it does

| Module | Description |
|--------|-------------|
| `honeypot/server.py` | Fake SSH server — captures every login attempt without letting anyone in |
| `honeypot/simulate.py` | Generates realistic attack data for demo/testing |
| `threatlens.py` | Main CLI analyzer — 7 commands to dissect attack patterns |

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate demo attack data (no cloud needed)
python honeypot/simulate.py --sessions 300 --hours 12

# 3. Run the analyzer
python threatlens.py summary
python threatlens.py top-ips
python threatlens.py top-creds
python threatlens.py timeline --hours 12
python threatlens.py fingerprint
python threatlens.py hunt --ip <attacker-ip>
python threatlens.py report --format html
```

---

## Commands

### `summary` — Attack overview
```
python threatlens.py summary
```
Shows total attempts, unique IPs, sessions, attack rate per hour.

### `top-ips` — Ranked attacker IPs
```
python threatlens.py top-ips --limit 20
```
Lists top attacking IPs with:
- Threat score (0–100) and severity label (CRITICAL / HIGH / MEDIUM / LOW)
- Tool fingerprint (Go scanner, Python bot, libssh, etc.)
- Unique usernames and passwords tried per IP

### `top-creds` — Most-tried credentials
```
python threatlens.py top-creds
```
Side-by-side frequency charts of most-attempted usernames and passwords.

### `timeline` — Attack frequency chart
```
python threatlens.py timeline --hours 6
```
ASCII bar chart showing attack intensity over time — spot burst attacks vs steady scans.

### `fingerprint` — Attacker tool identification
```
python threatlens.py fingerprint
```
Identifies attacker tools from SSH client version strings (Go scanners, Python bots, Java tools, etc.)

### `hunt` — IP investigation
```
python threatlens.py hunt --ip 123.58.10.5
```
Deep dive into a single attacker — all credential pairs tried, timing, threat score, tool used.

### `report` — Export HTML report
```
python threatlens.py report --format html
```
Generates a dark-themed HTML report saved to `reports/`.

### `live` — Real-time feed
```
python threatlens.py live
```
Watches the log file and prints new attacks as they happen.

---

## Running the real honeypot

```bash
# Run on port 2222 (no root needed unlike port 22)
python honeypot/server.py --port 2222

# Test it from another terminal
ssh -p 2222 root@localhost   # type any password — it logs it and rejects
```

The honeypot:
- Never grants access to anyone
- Logs every IP, username, password, SSH client version
- Rotates realistic SSH banner strings to appear genuine
- Handles concurrent connections with threading

---

## Skills demonstrated

- **Network programming** — raw socket server, SSH protocol via paramiko
- **CLI design** — argparse subcommands, rich terminal UI
- **Security concepts** — honeypots, threat scoring, IOC analysis, attacker fingerprinting
- **Data analysis** — log parsing, frequency analysis, pattern detection
- **Reporting** — HTML report generation

---

## Tech stack

- Python 3.10+
- `paramiko` — SSH protocol implementation
- `rich` — terminal UI (tables, colors, charts)

---

> ⚠️ **Educational use only.** Run only on systems you own or have permission to monitor.
