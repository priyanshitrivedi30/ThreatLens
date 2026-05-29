# 🛡️ ThreatLens v3.0

> A Python-based SSH honeypot and SOC dashboard that deploys a fake SSH server to capture, analyze, and visualize real-world brute-force attack patterns in real time.
---

## What is ThreatLens?

ThreatLens spins up a fake SSH server that looks real to attackers. Every login attempt — IP address, username, password, SSH client version — gets logged silently. You then analyze that data through a rich CLI or a live web dashboard, complete with geolocation, AbuseIPDB reputation scores, attacker tool fingerprinting, and desktop notifications.

Built for cybersecurity students and researchers who want to understand how SSH brute-force attacks actually work in the wild.

---

## Features

| Feature | Description |
|---|---|
| 🪤 SSH Honeypot | Paramiko-based fake SSH server — logs every auth attempt silently |
| 📟 CLI Analyzer | 8 commands — summary, top IPs, credentials, timeline, fingerprinting, hunt, report, live feed |
| 🖥️ SOC Dashboard | FastAPI + JS real-time web UI with attack map, charts, and live event feed |
| 🌍 IP Geolocation | ip-api.com free batch API — country, city, ASN. Cached locally, no key required |
| 🔴 AbuseIPDB | Community abuse confidence score (0–100%) shown as a badge per IP |
| 🧠 Threat Scoring | Scores each IP 0–100 as CRITICAL / HIGH / MEDIUM / LOW |
| 🔍 Tool Fingerprinting | Identifies attacker tools from SSH client version strings |
| 🔔 Desktop Notifications | Browser Notification API — alerts fire automatically for new CRITICAL IPs |
| 📄 HTML Reports | Dark-themed standalone HTML export |

---

## Project Structure

```
threatlens/
├── honeypot/
│   ├── server.py           SSH honeypot (Paramiko) — logs every auth attempt
│   └── simulate.py         Generate realistic demo attack data
├── dashboard/
│   ├── main.py             FastAPI backend (REST + SSE live feed)
│   └── static/             dashboard.html · app.js · style.css
├── logs/
│   ├── sessions.jsonl      Raw event log (written by honeypot or simulate.py)
│   ├── geo_cache.json      Geolocation cache (auto-created)
│   └── alerted.json        Fired alert history (auto-created)
├── geolocation.py          ip-api.com batch lookup, cached locally
├── alerting.py             Alert tracking logic
├── threatlens.py           CLI analyzer
├── requirements.txt
├── .env.example            Copy → .env and fill in optional keys
└── .env                    Your local config (never commit this)
```

---

## Quick Start

```bash
pip install -r requirements.txt

# Generate demo attack data
python honeypot/simulate.py --sessions 300

# Launch the web dashboard
cd dashboard
uvicorn main:app --reload
# → http://localhost:8000
```

When the dashboard opens in your browser, click **Allow** on the notification prompt to enable desktop alerts for CRITICAL IPs.

---

## CLI Commands

| Command | Description |
|---|---|
| `summary` | Total attempts, unique IPs, attack rate |
| `top-ips --limit N` | Ranked attacker table with threat score |
| `top-creds` | Most-tried usernames and passwords |
| `timeline --hours N` | Attack frequency chart over time |
| `fingerprint` | Attacker tool breakdown by SSH client string |
| `hunt --ip <address>` | Deep-dive on a single IP |
| `report` | Export dark-themed HTML report to `reports/` |
| `live` | Tail `sessions.jsonl` in real time |

```bash
python threatlens.py summary
python threatlens.py top-ips --limit 20
python threatlens.py top-creds
python threatlens.py timeline --hours 720
python threatlens.py fingerprint
python threatlens.py hunt --ip 123.58.95.14
python threatlens.py report
python threatlens.py live
```

---

## AbuseIPDB Setup (Optional)

1. Get a free API key at [abuseipdb.com](https://www.abuseipdb.com/register)
2. Add to your `.env`:

```env
ABUSEIPDB_KEY=your_key_here
```

Each flagged IP will show an abuse confidence score badge on the dashboard. Free tier: 1,000 checks/day. Results are cached locally so each IP is only queried once.

---

## Configuration

Copy `.env.example` to `.env`. Everything is optional.

| Variable | Description |
|---|---|
| `ABUSEIPDB_KEY` | AbuseIPDB API key for IP reputation scores |
| `ALERT_THRESHOLD` | Attempt count to trigger a desktop alert (default: 20) |
| `AUTO_CLEAR_ALERTS` | Clear alert history on every restart — `true` / `false` |

---

## Docker

```bash
cd dashboard
docker compose up --build
# → http://localhost:8000
```

---

## Disclaimer

> **For educational and research use only.** Only run the honeypot on infrastructure you own and control. Never deploy on a machine with sensitive data or on networks you don't have explicit permission to monitor.
