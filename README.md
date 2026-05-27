# ThreatLens v3.0 — SSH Honeypot & SOC Dashboard

Real-time SSH brute-force detection with a CLI analyzer and live web dashboard.

```
threatlens/
├── honeypot/
│   ├── server.py       SSH honeypot (Paramiko) — logs every auth attempt
│   └── simulate.py     Generate realistic demo attack data
├── dashboard/
│   ├── main.py         FastAPI backend (REST + SSE)
│   └── static/         dashboard.html · app.js · style.css
├── logs/
│   ├── sessions.jsonl  Raw event log (written by honeypot/simulate)
│   ├── geo_cache.json  Geolocation cache (auto-created)
│   └── alerted.json    Fired alert history (auto-created)
├── geolocation.py      ip-api.com batch lookup, cached in geo_cache.json
├── alerting.py         Slack + email alerts, tracked in alerted.json
├── threatlens.py       CLI analyzer
├── requirements.txt
└── .env.example        Copy → .env and fill in optional keys
```

## Quick start

```bash
pip install -r requirements.txt

# 1. Generate demo data (or run the real honeypot)
python honeypot/simulate.py --sessions 300

# 2. Start the web dashboard
cd dashboard
uvicorn main:app --reload
# → http://localhost:8000

# 3. Or use the CLI
python threatlens.py summary
python threatlens.py top-ips --limit 20
python threatlens.py top-creds
python threatlens.py timeline --hours 24
python threatlens.py fingerprint
python threatlens.py hunt --ip 123.58.95.14
python threatlens.py report
python threatlens.py live
```

## v3.0 improvements

| Feature | How it works |
|---|---|
| **IP Geolocation** | ip-api.com free batch API — no key required. Results cached in `logs/geo_cache.json` so each IP is only looked up once. Country flag + city shown in the IP table and live feed. |
| **AbuseIPDB enrichment** | Community abuse confidence score merged *into* local data. Shows as a `%` badge next to each IP. Optional — works without a key. |
| **Slack + email alerts** | Fires when a new CRITICAL IP is detected. Each IP alerted only once (tracked in `logs/alerted.json`). Both channels are optional. |

## Configuration (optional)

```bash
cp .env.example .env
# edit .env, then:
export $(cat .env | xargs)
cd dashboard && uvicorn main:app --reload
```

## Educational use only
