"""
ThreatLens — Real-Time SOC Dashboard Backend  v3.0
===================================================
  • Geolocation  — ip-api.com batch lookup, cached in logs/geo_cache.json
  • AbuseIPDB    — merges abuse score into local data (not replaces)
  • Alerting     — Slack (optional) + browser desktop notifications via SSE
                   New critical IPs are pushed through /api/feed as alert events

Endpoints:
  GET /            → dashboard HTML
  GET /api/stats   → full threat data JSON
  GET /api/ips     → flagged IPs only
  GET /api/alerts  → all fired alerts history
  GET /api/feed    → live SSE stream (attacks + alert events)
  GET /api/health  → health check
"""

import os, sys, time, json, asyncio, threading, random
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import AsyncGenerator

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import httpx
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

import geolocation as geo
from alerting import check_and_fire, ALERTED_FILE, ALERT_THRESHOLD
from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
SHARED_LOG    = ROOT / "logs" / "sessions.jsonl"
STATIC_DIR    = Path(__file__).parent / "static"

app = FastAPI(title="ThreatLens SOC Dashboard API", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ── SSE event feed ─────────────────────────────────────────────────────────────
# Two event types flow through here:
#   {"type": "attack",  ip, user, country, ...}
#   {"type": "alert",   ip, attempts, country, city, fired_at}
event_feed: list[dict] = []
feed_lock  = threading.Lock()

def push(event: dict):
    with feed_lock:
        event_feed.append(event)
        if len(event_feed) > 500:
            event_feed.pop(0)


# ── JSONL parser ───────────────────────────────────────────────────────────────

def parse_shared_log() -> dict | None:
    if not SHARED_LOG.exists():
        return None

    ip_counts   = defaultdict(int)
    user_counts = defaultdict(int)
    hour_counts = defaultdict(int)
    recent      = []

    try:
        lines = SHARED_LOG.read_text(errors="replace").splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                if e.get("event") != "auth_attempt":
                    continue
                ip   = e.get("src_ip")
                user = e.get("username", "unknown")
                ts   = e.get("logged_at", "")
                hour = int(ts[11:13]) if len(ts) >= 13 else 0
                if ip:
                    ip_counts[ip]     += 1
                    hour_counts[hour] += 1
                    if len(recent) < 50:
                        recent.append({"ip": ip, "user": user, "ts": ts[11:19]})
                user_counts[user] += 1
            except Exception:
                pass
    except Exception:
        return None

    if not ip_counts:
        return None

    geo_cache = geo.get_all()
    ips = []
    for ip, attempts in sorted(ip_counts.items(), key=lambda x: -x[1]):
        g = geo_cache.get(ip, {})
        ips.append({
            "ip":           ip,
            "attempts":     attempts,
            "country":      g.get("country", "??"),
            "country_code": g.get("country_code", ""),
            "city":         g.get("city", ""),
            "latitude":     g.get("latitude"),
            "longitude":    g.get("longitude"),
        })

    return {
        "ips":        ips,
        "usernames":  sorted(
            [{"name": k, "count": v} for k, v in user_counts.items()],
            key=lambda x: -x["count"]
        )[:10],
        "timeline":   [hour_counts.get(h, 0) for h in range(24)],
        "recent":     list(reversed(recent[-20:])),
        "total":      sum(ip_counts.values()),
        "unique_ips": len(ip_counts),
    }


# ── Background workers ─────────────────────────────────────────────────────────

def background_worker():
    """Watches sessions.jsonl, pushes new auth events + triggers geo enrichment."""
    seen_lines = 0
    while True:
        try:
            if SHARED_LOG.exists():
                lines     = SHARED_LOG.read_text(errors="replace").splitlines()
                new_lines = lines[seen_lines:]
                seen_lines = len(lines)

                new_ips = []
                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                        if e.get("event") == "auth_attempt":
                            ip      = e.get("src_ip", "?")
                            user    = e.get("username", "?")
                            g       = geo.get(ip)
                            country = g.get("country", "")
                            push({"type": "attack", "ip": ip, "user": user,
                                  "country": country,
                                  "country_code": g.get("country_code", ""),
                                  "timestamp": datetime.now().strftime("%H:%M:%S")})
                            new_ips.append(ip)
                    except Exception:
                        pass

                if new_ips:
                    threading.Thread(
                        target=geo.enrich_ips, args=(list(set(new_ips)),), daemon=True
                    ).start()

        except Exception as e:
            print(f"  [worker] {e}")
        time.sleep(5)


def alert_worker():
    """
    Runs every 30s. Checks for new CRITICAL IPs and pushes alert events
    through the SSE feed so the browser can show desktop notifications.
    """
    while True:
        try:
            log = parse_shared_log()
            if log:
                new_alerts = check_and_fire(log["ips"])
                for alert in new_alerts:
                    push({"type": "alert", **alert})
        except Exception as e:
            print(f"  [alert-worker] {e}")
        time.sleep(30)


# ── AbuseIPDB enrichment ───────────────────────────────────────────────────────
# Results are cached in logs/abuse_cache.json so each IP only costs 1 API call.
# Free tier allows 1,000 checks/day; cached IPs are never re-fetched.

ABUSE_CACHE_FILE = ROOT / "logs" / "abuse_cache.json"
_abuse_cache: dict[str, dict] = {}
_abuse_lock = threading.Lock()


def _load_abuse_cache():
    global _abuse_cache
    if ABUSE_CACHE_FILE.exists():
        try:
            _abuse_cache = json.loads(ABUSE_CACHE_FILE.read_text())
        except Exception:
            _abuse_cache = {}


def _save_abuse_cache():
    ABUSE_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    ABUSE_CACHE_FILE.write_text(json.dumps(_abuse_cache, indent=2))


async def fetch_abuse_scores(ips: list[str]) -> dict[str, dict]:
    """
    Returns abuse scores for the given IPs.
    - Hits cache first; only queries AbuseIPDB for IPs not yet cached.
    - Silently returns empty dict if ABUSEIPDB_KEY is not set.
    - Caps live requests at 50 per call to stay within free-tier daily limits.
    """
    if not ABUSEIPDB_KEY or not ips:
        return {}

    with _abuse_lock:
        if not _abuse_cache:
            _load_abuse_cache()
        # Serve cached results immediately
        results = {ip: _abuse_cache[ip] for ip in ips if ip in _abuse_cache}
        uncached = [ip for ip in ips if ip not in _abuse_cache]

    if not uncached:
        return results

    # Fetch up to 50 uncached IPs (free tier: 1,000/day)
    async with httpx.AsyncClient(timeout=8) as client:
        for ip in uncached[:50]:
            try:
                r = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                )
                if r.status_code == 200:
                    d = r.json().get("data", {})
                    entry = {
                        "abuse_score":   d.get("abuseConfidenceScore", 0),
                        "total_reports": d.get("totalReports", 0),
                        "domain":        d.get("domain", ""),
                        "isp":           d.get("isp", ""),
                        "cached_at":     datetime.now().strftime("%Y-%m-%d"),
                    }
                    with _abuse_lock:
                        _abuse_cache[ip] = entry
                        _save_abuse_cache()
                    results[ip] = entry
                elif r.status_code == 429:
                    # Rate limited — stop and return what we have
                    print("  [abuseipdb] Rate limited — stopping early")
                    break
            except Exception as e:
                print(f"  [abuseipdb] Error for {ip}: {e}")

    return results


def build_response(log: dict, abuse: dict, threshold: int, source: str) -> dict:
    ips = []
    for entry in log["ips"]:
        att    = entry["attempts"]
        status = "CRITICAL" if att >= 20 else "FLAGGED" if att >= threshold else "NORMAL"
        row    = {**entry, "status": status, "abuse_score": None, "total_reports": None}
        if entry["ip"] in abuse:
            row.update(abuse[entry["ip"]])
        ips.append(row)

    return {
        "ips":           ips,
        "usernames":     log["usernames"],
        "timeline":      log["timeline"],
        "recent_events": log["recent"],
        "total_events":  log["total"],
        "unique_ips":    log["unique_ips"],
        "flagged_count": sum(1 for i in ips if i["status"] != "NORMAL"),
        "threshold":     threshold,
        "source":        source,
        "scanned_at":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root():
    f = STATIC_DIR / "dashboard.html"
    return HTMLResponse(f.read_text(encoding="utf-8") if f.exists() else "<h1>dashboard.html missing</h1>")


@app.get("/api/stats")
async def stats(threshold: int = Query(5)):
    log = parse_shared_log()
    if not log:
        return JSONResponse({"ips": [], "usernames": [], "timeline": [0]*24,
                             "total_events": 0, "unique_ips": 0, "flagged_count": 0,
                             "threshold": threshold, "source": "no data yet",
                             "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    abuse  = await fetch_abuse_scores([d["ip"] for d in log["ips"][:20]])
    return JSONResponse(build_response(log, abuse, threshold, "ThreatLens Honeypot (sessions.jsonl)"))


@app.get("/api/ips")
async def get_ips(threshold: int = Query(5)):
    r    = await stats(threshold)
    data = json.loads(r.body)
    return JSONResponse({
        "flagged_ips": [i for i in data["ips"] if i.get("status") != "NORMAL"],
        "count":       data["flagged_count"],
    })


@app.get("/api/alerts")
async def get_alerts():
    """All fired alerts — enriched with current attempt counts and geo."""
    alerts = []
    if ALERTED_FILE.exists():
        try:
            fired_ips = json.loads(ALERTED_FILE.read_text())
            log       = parse_shared_log()
            ip_map    = {d["ip"]: d for d in log["ips"]} if log else {}
            for ip in fired_ips:
                entry = ip_map.get(ip, {})
                alerts.append({
                    "ip":           ip,
                    "attempts":     entry.get("attempts", "?"),
                    "country":      entry.get("country", "??"),
                    "country_code": entry.get("country_code", ""),
                    "city":         entry.get("city", ""),
                })
        except Exception:
            pass
    return JSONResponse({"alerts": alerts, "count": len(alerts), "threshold": ALERT_THRESHOLD})


@app.get("/api/feed")
async def live_feed():
    async def gen() -> AsyncGenerator[str, None]:
        idx = len(event_feed)
        while True:
            await asyncio.sleep(2)
            with feed_lock:
                new = event_feed[idx:]
                idx = len(event_feed)
            for ev in new:
                yield f"data: {json.dumps(ev)}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/health")
async def health():
    with _abuse_lock:
        abuse_cached = len(_abuse_cache)
    return {
        "status":        "online",
        "honeypot_log":  SHARED_LOG.exists(),
        "geo_cached":    len(geo.get_all()),
        "abuseipdb":     bool(ABUSEIPDB_KEY),
        "abuse_cached":  abuse_cached,
        "slack_alerts":  bool(os.getenv("SLACK_WEBHOOK_URL")),
        "time":          datetime.now().isoformat(),
    }


@app.on_event("startup")
async def startup():
    threading.Thread(target=background_worker, daemon=True).start()
    threading.Thread(target=alert_worker,      daemon=True).start()

    _load_abuse_cache()
    
    if os.getenv("AUTO_CLEAR_ALERTS", "false").lower() == "true":
        if (ROOT / "logs" / "alerted.json").exists():
            (ROOT / "logs" / "alerted.json").unlink()
            print("  Alerts cleared on startup")   

    log = parse_shared_log()
    if log:
        threading.Thread(
            target=geo.enrich_ips, args=([d["ip"] for d in log["ips"]],), daemon=True
        ).start()

    print("=" * 60)
    print("  ThreatLens SOC Dashboard v3.0")
    print(f"  Honeypot log  : {'✅ FOUND' if SHARED_LOG.exists() else '⚠️  not found'}")
    print(f"  AbuseIPDB     : {'✅ SET' if ABUSEIPDB_KEY else '⚠️  not set'}")
    with _abuse_lock:
        print(f"  Abuse cache   : {len(_abuse_cache)} IPs cached")
    print(f"  Slack alerts  : {'✅ SET' if os.getenv('SLACK_WEBHOOK_URL') else '⚠️  not set'}")
    print(f"  Desktop notifs: ✅ handled by browser Notification API")
    print(f"  Dashboard     : http://localhost:8000")
    print("=" * 60)
