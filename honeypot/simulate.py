"""
ThreatLens — Attack Simulator
Generates realistic fake SSH attack logs for demo/portfolio purposes.
Run this when you don't have live attackers yet.
"""

import json
import random
import time
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "sessions.jsonl"

# Real-world attack patterns
USERNAMES = [
    "root", "admin", "ubuntu", "pi", "user", "test", "oracle", "mysql",
    "postgres", "git", "deploy", "ansible", "vagrant", "ec2-user",
    "hadoop", "tomcat", "www-data", "jenkins", "ftpuser", "guest",
    "support", "operator", "nagios", "backup", "mail", "ftp", "ssh",
]

PASSWORDS = [
    "123456", "password", "admin", "root", "12345678", "qwerty", "abc123",
    "letmein", "monkey", "1234567890", "password1", "iloveyou", "admin123",
    "welcome", "login", "passw0rd", "master", "hello", "shadow", "dragon",
    "sunshine", "princess", "football", "P@ssw0rd", "Admin@123", "root123",
    "toor", "raspberry", "alpine", "changeme", "test123", "ubnt", "default",
    "1q2w3e4r", "123qwe", "pass", "password123", "administrator",
]

CLIENT_VERSIONS = [
    "SSH-2.0-libssh2_1.10.0",
    "SSH-2.0-Go",
    "SSH-2.0-PUTTY",
    "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-python-paramiko_3.4.0",
    "SSH-2.0-libssh_0.10.5",
    "SSH-2.0-AsyncSSH_2.14.0",
    "SSH-2.0-Granados-1.0",
    "SSH-2.0-RubyNetSSH_7.0.1",
    "SSH-2.0-JSCH-0.2.15",
]

# Simulated attacker IP pools by "country/ASN cluster"
ATTACKER_POOLS = {
    "CN": ["123.58.{}.{}".format(random.randint(0,255), random.randint(1,254)) for _ in range(20)],
    "RU": ["95.213.{}.{}".format(random.randint(0,255), random.randint(1,254)) for _ in range(15)],
    "US": ["45.33.{}.{}".format(random.randint(0,255), random.randint(1,254)) for _ in range(10)],
    "DE": ["46.101.{}.{}".format(random.randint(0,255), random.randint(1,254)) for _ in range(8)],
    "NL": ["185.220.{}.{}".format(random.randint(0,255), random.randint(1,254)) for _ in range(8)],
    "BR": ["189.1.{}.{}".format(random.randint(0,255), random.randint(1,254)) for _ in range(6)],
    "IN": ["103.87.{}.{}".format(random.randint(0,255), random.randint(1,254)) for _ in range(6)],
    "KR": ["1.11.{}.{}".format(random.randint(0,255), random.randint(1,254)) for _ in range(5)],
}

ALL_IPS = [(ip, country) for country, ips in ATTACKER_POOLS.items() for ip in ips]


def make_session(base_time: datetime, ip: str, country: str):
    events = []
    port = random.randint(40000, 65000)
    client = random.choice(CLIENT_VERSIONS)
    t = base_time

    # Connect
    events.append({
        "event": "connect",
        "src_ip": ip,
        "src_port": port,
        "client_version": client,
        "country": country,
        "logged_at": t.isoformat(),
    })
    t += timedelta(seconds=random.uniform(0.1, 0.5))

    # Auth attempts (bots do many in sequence)
    n_attempts = random.choices([1, 3, 5, 10, 20, 50], weights=[5, 15, 25, 30, 20, 5])[0]
    for _ in range(n_attempts):
        user = random.choice(USERNAMES)
        pwd = random.choice(PASSWORDS)
        events.append({
            "event": "auth_attempt",
            "src_ip": ip,
            "src_port": port,
            "username": user,
            "password": pwd,
            "method": "password",
            "country": country,
            "logged_at": t.isoformat(),
        })
        t += timedelta(seconds=random.uniform(0.05, 0.3))

    # Disconnect
    events.append({
        "event": "disconnect",
        "src_ip": ip,
        "src_port": port,
        "country": country,
        "logged_at": t.isoformat(),
    })
    return events


def simulate(n_sessions: int = 200, spread_hours: int = 6, verbose: bool = True):
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=spread_hours)

    all_events = []
    for _ in range(n_sessions):
        ip, country = random.choice(ALL_IPS)
        t = start + timedelta(seconds=random.uniform(0, spread_hours * 3600))
        all_events.extend(make_session(t, ip, country))

    all_events.sort(key=lambda e: e["logged_at"])

    with open(LOG_FILE, "a") as f:
        for ev in all_events:
            f.write(json.dumps(ev) + "\n")

    if verbose:
        sessions = sum(1 for e in all_events if e["event"] == "connect")
        attempts = sum(1 for e in all_events if e["event"] == "auth_attempt")
        unique_ips = len(set(e["src_ip"] for e in all_events))
        print(f"\n  \033[32m[+]\033[0m Simulated {sessions} sessions, {attempts} auth attempts from {unique_ips} unique IPs")
        print(f"  \033[32m[+]\033[0m Written to {LOG_FILE}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate fake SSH attack logs for ThreatLens demo")
    parser.add_argument("--sessions", type=int, default=200, help="Number of attacker sessions (default: 200)")
    parser.add_argument("--hours", type=int, default=6, help="Spread attacks over N hours (default: 6)")
    args = parser.parse_args()
    simulate(n_sessions=args.sessions, spread_hours=args.hours)
