"""
ThreatLens — IP Geolocation
Uses ip-api.com batch endpoint (free, no API key, up to 100 IPs per call).
Results are cached in a lightweight JSON file so each IP is looked up once.
No database dependency.
"""

import json
import time
import threading
from pathlib import Path

import httpx

CACHE_FILE  = Path(__file__).parent / "logs" / "geo_cache.json"
_batch_size = 100
_rate_delay = 1.0      # seconds between batch calls (free tier: 45 req/min)
_lock       = threading.Lock()

# In-memory cache: {ip: {country, country_code, city, asn, latitude, longitude}}
_cache: dict[str, dict] = {}


def _load_cache():
    global _cache
    if CACHE_FILE.exists():
        try:
            _cache = json.loads(CACHE_FILE.read_text())
        except Exception:
            _cache = {}


def _save_cache():
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(_cache, indent=2))


def _store_results(results: list[dict]):
    for r in results:
        if r.get("status") != "success":
            continue
        ip = r.get("query")
        if ip:
            _cache[ip] = {
                "country":      r.get("country", ""),
                "country_code": r.get("countryCode", ""),
                "city":         r.get("city", ""),
                "region":       r.get("regionName", ""),
                "asn":          r.get("as", ""),
                "org":          r.get("org", ""),
                "latitude":     r.get("lat"),
                "longitude":    r.get("lon"),
            }
    _save_cache()


def lookup_batch(ips: list[str]) -> list[dict]:
    if not ips:
        return []
    try:
        resp = httpx.post(
            "http://ip-api.com/batch",
            json=[{"query": ip} for ip in ips],
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return []


def enrich_ips(ips: list[str]):
    """
    Look up any IPs not already in cache.
    Called from a background thread — safe to call frequently.
    """
    with _lock:
        if not _cache:
            _load_cache()
        to_fetch = [ip for ip in ips if ip and ip not in _cache]

    if not to_fetch:
        return

    for i in range(0, len(to_fetch), _batch_size):
        batch   = to_fetch[i : i + _batch_size]
        results = lookup_batch(batch)
        with _lock:
            _store_results(results)
        time.sleep(_rate_delay)


def get(ip: str) -> dict:
    """Return cached geo info for an IP, or empty dict if not cached yet."""
    with _lock:
        if not _cache:
            _load_cache()
        return _cache.get(ip, {})


def get_all() -> dict[str, dict]:
    with _lock:
        if not _cache:
            _load_cache()
        return dict(_cache)
