"""
ThreatLens — Alerting
Desktop notifications are handled client-side via the browser Notification API (app.js).
This backend module only handles Slack webhook (optional).
Tracks fired alerts in logs/alerted.json so each IP is alerted only once.

Environment variables:
    SLACK_WEBHOOK_URL  — https://hooks.slack.com/services/...
    ALERT_THRESHOLD    — attempt count to trigger (default: 20)
"""

import os
import json
import threading
from datetime import datetime
from pathlib import Path

import httpx

SLACK_WEBHOOK   = os.getenv("SLACK_WEBHOOK_URL", "")
ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "20"))

ALERTED_FILE = Path(__file__).parent / "logs" / "alerted.json"
_lock        = threading.Lock()
_alerted: set[str] = set()


def _load_alerted():
    if ALERTED_FILE.exists():
        try:
            _alerted.update(json.loads(ALERTED_FILE.read_text()))
        except Exception:
            pass


def _save_alerted():
    ALERTED_FILE.parent.mkdir(parents=True, exist_ok=True)
    ALERTED_FILE.write_text(json.dumps(list(_alerted)))


# ── Slack (optional) ───────────────────────────────────────────────────────────

def send_slack(ip: str, attempts: int, country: str) -> bool:
    if not SLACK_WEBHOOK:
        return False
    flag = f":flag-{country.lower()}:" if country and country not in ("??", "") else ":globe_with_meridians:"
    payload = {
        "text": ":rotating_light: *ThreatLens CRITICAL Alert*",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "🚨 ThreatLens — CRITICAL IP Detected"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*IP Address:*\n`{ip}`"},
                {"type": "mrkdwn", "text": f"*Attempts:*\n{attempts:,}"},
                {"type": "mrkdwn", "text": f"*Country:*\n{flag} {country or 'Unknown'}"},
                {"type": "mrkdwn", "text": f"*Detected:*\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"},
            ]},
            {"type": "context", "elements": [
                {"type": "mrkdwn", "text": "ThreatLens SSH Honeypot · Educational Use Only"}
            ]},
        ],
    }
    try:
        r = httpx.post(SLACK_WEBHOOK, json=payload, timeout=8)
        return r.status_code == 200
    except Exception as e:
        print(f"  [alert] Slack error: {e}")
        return False


# ── Main check (called by alert_worker in main.py) ─────────────────────────────

def check_and_fire(ip_data: list[dict]) -> list[dict]:
    """
    Checks ip_data for new CRITICAL IPs.
    Fires Slack if configured.
    Returns list of NEW alerts (to be pushed via SSE to the browser for desktop notifications).
    """
    new_alerts = []

    with _lock:
        if not _alerted:
            _load_alerted()

        for entry in ip_data:
            ip      = entry.get("ip", "")
            att     = entry.get("attempts", 0)
            country = entry.get("country", "")

            if att < ALERT_THRESHOLD or ip in _alerted:
                continue

            send_slack(ip, att, country)
            _alerted.add(ip)
            _save_alerted()

            alert = {
                "ip":       ip,
                "attempts": att,
                "country":  country,
                "city":     entry.get("city", ""),
                "country_code": entry.get("country_code", ""),
                "fired_at": datetime.now().strftime("%H:%M:%S"),
            }
            new_alerts.append(alert)
            print(f"  [alert] CRITICAL {ip} ({att} attempts, {country})")

    return new_alerts
