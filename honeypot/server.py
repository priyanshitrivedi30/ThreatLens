"""
ThreatLens SSH Honeypot Server
Listens on a configurable port, logs every connection and auth attempt.
"""

import socket
import threading
import json
import os
import time
import argparse
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path

try:
    import paramiko
    from paramiko import RSAKey, ServerInterface, Transport
    from paramiko.common import AUTH_FAILED, OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
except ImportError:
    print("[!] Missing dependency: pip install paramiko")
    raise

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "sessions.jsonl"

# ── Banner pool (rotated to look realistic) ────────────────────────────────────
BANNERS = [
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
    "SSH-2.0-OpenSSH_9.0",
    "SSH-2.0-dropbear_2022.83",
]

_banner_idx = 0

def next_banner():
    global _banner_idx
    b = BANNERS[_banner_idx % len(BANNERS)]
    _banner_idx += 1
    return b


def log_event(event: dict):
    event["logged_at"] = datetime.now(timezone.utc).isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    ts = event["logged_at"][11:19]
    ip = event.get("src_ip", "?")
    etype = event.get("event", "?")
    user = event.get("username", "")
    pwd = event.get("password", "")
    if etype == "auth_attempt":
        print(f"  \033[33m[{ts}]\033[0m {ip:>15}  AUTH  {user!r:12} / {pwd!r}")
    elif etype == "connect":
        print(f"  \033[36m[{ts}]\033[0m {ip:>15}  CONNECT  client={event.get('client_version','?')[:40]}")
    elif etype == "disconnect":
        print(f"  \033[90m[{ts}]\033[0m {ip:>15}  DISCONNECT")


class HoneypotServer(ServerInterface):
    def __init__(self, client_ip: str, client_port: int):
        self.client_ip = client_ip
        self.client_port = client_port
        self.username = None

    def check_auth_password(self, username: str, password: str) -> int:
        log_event({
            "event": "auth_attempt",
            "src_ip": self.client_ip,
            "src_port": self.client_port,
            "username": username,
            "password": password,
            "method": "password",
        })
        # Always fail — we never let anyone in
        return AUTH_FAILED

    def check_auth_publickey(self, username: str, key) -> int:
        fp = key.get_fingerprint().hex()
        log_event({
            "event": "auth_attempt",
            "src_ip": self.client_ip,
            "src_port": self.client_port,
            "username": username,
            "key_fingerprint": fp,
            "key_type": key.get_name(),
            "method": "publickey",
        })
        return AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password,publickey"


def generate_host_key():
    key_path = LOG_DIR.parent / ".host_key"
    if key_path.exists():
        return RSAKey(filename=str(key_path))
    key = RSAKey.generate(2048)
    key.write_private_key_file(str(key_path))
    return key


def handle_client(conn: socket.socket, addr: tuple, host_key, banner: str):
    ip, port = addr
    log_event({"event": "connect", "src_ip": ip, "src_port": port, "client_version": ""})
    try:
        transport = Transport(conn)
        transport.local_version = banner
        transport.add_server_key(host_key)
        server = HoneypotServer(ip, port)

        try:
            transport.start_server(server=server)
        except Exception:
            pass

        # Wait a bit to capture auth attempts before closing
        chan = transport.accept(timeout=20)
        if chan:
            chan.close()

        # Capture client version after negotiation
        cv = transport.remote_version or ""
        if cv:
            log_event({"event": "connect", "src_ip": ip, "src_port": port, "client_version": cv})

    except Exception:
        pass
    finally:
        log_event({"event": "disconnect", "src_ip": ip, "src_port": port})
        try:
            conn.close()
        except Exception:
            pass


def run(port: int = 2222, host: str = "0.0.0.0"):
    host_key = generate_host_key()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)

    print(f"\n  \033[32m╔══════════════════════════════════════════╗\033[0m")
    print(f"  \033[32m║     ThreatLens SSH Honeypot  v1.0        ║\033[0m")
    print(f"  \033[32m╚══════════════════════════════════════════╝\033[0m")
    print(f"  Listening on  \033[1m{host}:{port}\033[0m")
    print(f"  Logging to    \033[1m{LOG_FILE}\033[0m")
    print(f"  Press Ctrl+C to stop\n")

    try:
        while True:
            try:
                conn, addr = sock.accept()
                banner = next_banner()
                t = threading.Thread(target=handle_client, args=(conn, addr, host_key, banner), daemon=True)
                t.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"  [!] Accept error: {e}")
    finally:
        sock.close()
        print("\n  [*] Honeypot stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ThreatLens SSH Honeypot")
    parser.add_argument("--port", type=int, default=2222, help="Port to listen on (default: 2222)")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    args = parser.parse_args()
    run(port=args.port, host=args.host)
