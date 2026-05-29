#!/usr/bin/env python3
"""
ThreatLens — SSH Honeypot Analyzer
A professional CLI tool to analyze SSH brute-force attack data.

Usage:
    python threatlens.py summary
    python threatlens.py top-ips --limit 20
    python threatlens.py top-creds
    python threatlens.py timeline --hours 6
    python threatlens.py fingerprint
    python threatlens.py hunt --ip 123.58.10.5
    python threatlens.py report --format html
    python threatlens.py live
"""

import json
import sys
import os
import argparse
import time
import hashlib
import threading
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import track
    from rich import box
    from rich.columns import Columns
    from rich.live import Live
    from rich.layout import Layout
    from rich.rule import Rule
    from rich.syntax import Syntax
    import rich.style
except ImportError:
    print("[!] Missing dependency: pip install rich")
    sys.exit(1)

LOG_DIR = Path(__file__).parent / "logs"
LOG_FILE = LOG_DIR / "sessions.jsonl"
REPORT_DIR = Path(__file__).parent / "reports"
REPORT_DIR.mkdir(exist_ok=True)

console = Console()

# ── Palette ───────────────────────────────────────────────────────────────────
C_RED    = "bold red"
C_GREEN  = "bold green"
C_YELLOW = "bold yellow"
C_CYAN   = "bold cyan"
C_DIM    = "dim"
C_WHITE  = "bold white"

BANNER = r"""
  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗██╗     ███████╗███╗   ██╗███████╗
  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║     ██╔════╝████╗  ██║██╔════╝
     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██║     █████╗  ██╔██╗ ██║███████╗
     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║     ██╔══╝  ██║╚██╗██║╚════██║
     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ███████╗███████╗██║ ╚████║███████║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
"""

# ── Data loading ──────────────────────────────────────────────────────────────

def load_events() -> list[dict]:
    if not LOG_FILE.exists():
        console.print(f"\n  [red]✗[/red] Log file not found: [dim]{LOG_FILE}[/dim]")
        console.print("  Run [cyan]python honeypot/simulate.py[/cyan] to generate demo data first.\n")
        sys.exit(1)
    events = []
    with open(LOG_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def parse_time(s: str) -> datetime:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def events_in_window(events: list, hours: int) -> list:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    return [e for e in events if parse_time(e.get("logged_at", "")) >= cutoff]


# ── Threat scoring ────────────────────────────────────────────────────────────

def score_ip(attempts: int, unique_users: int, unique_passwords: int, client: str) -> tuple[int, str]:
    score = 0
    score += min(attempts * 2, 60)
    score += min(unique_users * 3, 20)
    score += min(unique_passwords * 2, 15)
    known_scanners = ["Go", "python-paramiko", "libssh2", "AsyncSSH", "masscan", "zgrab"]
    if any(s.lower() in client.lower() for s in known_scanners):
        score += 10
    score = min(score, 100)
    if score >= 75:
        label = "[bold red]● CRITICAL[/bold red]"
    elif score >= 50:
        label = "[bold yellow]● HIGH[/bold yellow]"
    elif score >= 25:
        label = "[bold cyan]● MEDIUM[/bold cyan]"
    else:
        label = "[dim]● LOW[/dim]"
    return score, label


def fingerprint_tool(client_version: str) -> str:
    cv = client_version.lower()
    if "go" in cv:           return "🤖 Go scanner (Shodan/Masscan-style)"
    if "paramiko" in cv:     return "🐍 Python bot (paramiko)"
    if "libssh2" in cv:      return "⚙️  C library scanner"
    if "asyncssh" in cv:     return "⚡ Async Python bot"
    if "putty" in cv:        return "🖥️  PuTTY (possibly human)"
    if "openssh" in cv:      return "🐧 OpenSSH client"
    if "jsch" in cv:         return "☕ Java bot (JSch)"
    if "ruby" in cv:         return "💎 Ruby bot (Net::SSH)"
    if "libssh_" in cv:      return "📦 libssh scanner"
    return "❓ Unknown tool"


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_summary(events: list):
    auth    = [e for e in events if e.get("event") == "auth_attempt"]
    connect = [e for e in events if e.get("event") == "connect"]
    unique_ips   = len(set(e["src_ip"] for e in events if "src_ip" in e))
    unique_users = len(set(e["username"] for e in auth if "username" in e))
    unique_pwds  = len(set(e["password"] for e in auth if "password" in e))

    times = [parse_time(e["logged_at"]) for e in events if "logged_at" in e]
    if times:
        span = max(times) - min(times)
        rate = len(auth) / max(span.total_seconds() / 3600, 0.01)
    else:
        span = timedelta(0)
        rate = 0

    console.print(f"\n[bold cyan]  SSH Honeypot — Attack Summary[/bold cyan]")
    console.print(f"  [dim]{'─' * 46}[/dim]\n")

    grid = Table.grid(padding=(0, 4))
    grid.add_column(style="dim", width=26)
    grid.add_column(style="bold white")

    grid.add_row("Total auth attempts",   f"[red]{len(auth):,}[/red]")
    grid.add_row("Unique attacker IPs",   f"[yellow]{unique_ips:,}[/yellow]")
    grid.add_row("Unique sessions",       f"{len(connect):,}")
    grid.add_row("Unique usernames tried",f"[cyan]{unique_users:,}[/cyan]")
    grid.add_row("Unique passwords tried",f"[cyan]{unique_pwds:,}[/cyan]")
    grid.add_row("Observation window",    str(span).split(".")[0])
    grid.add_row("Attack rate",           f"[bold red]{rate:.1f}[/bold red] attempts/hr")

    console.print(grid)
    console.print()


def cmd_top_ips(events: list, limit: int = 15):
    auth = [e for e in events if e.get("event") == "auth_attempt"]
    connect_events = [e for e in events if e.get("event") == "connect"]

    ip_attempts  = Counter(e["src_ip"] for e in auth if "src_ip" in e)
    ip_users     = defaultdict(set)
    ip_passwords = defaultdict(set)
    ip_client    = {}

    for e in auth:
        ip = e.get("src_ip", "")
        if e.get("username"): ip_users[ip].add(e["username"])
        if e.get("password"): ip_passwords[ip].add(e["password"])

    for e in connect_events:
        ip = e.get("src_ip", "")
        cv = e.get("client_version", "")
        if cv and ip not in ip_client:
            ip_client[ip] = cv

    table = Table(
        title=f"[bold]Top {limit} Attacking IPs[/bold]",
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        title_style="bold white",
        padding=(0, 1),
    )
    table.add_column("#",           width=4,  justify="right",  style="dim")
    table.add_column("IP Address",  width=18)
    table.add_column("Attempts",    width=10, justify="right")
    table.add_column("Uniq Users",  width=11, justify="right")
    table.add_column("Uniq Pwds",   width=10, justify="right")
    table.add_column("Threat",      width=16)
    table.add_column("Tool Fingerprint", min_width=28)

    for rank, (ip, count) in enumerate(ip_attempts.most_common(limit), 1):
        client = ip_client.get(ip, "")
        score, label = score_ip(count, len(ip_users[ip]), len(ip_passwords[ip]), client)
        fp = fingerprint_tool(client)
        table.add_row(
            str(rank),
            f"[white]{ip}[/white]",
            f"[red]{count:,}[/red]",
            str(len(ip_users[ip])),
            str(len(ip_passwords[ip])),
            label,
            fp,
        )

    console.print()
    console.print(table)
    console.print()


def cmd_top_creds(events: list, limit: int = 20):
    auth = [e for e in events if e.get("event") == "auth_attempt"]

    top_users = Counter(e["username"] for e in auth if "username" in e).most_common(limit)
    top_pwds  = Counter(e["password"] for e in auth if "password" in e).most_common(limit)

    max_u = top_users[0][1] if top_users else 1
    max_p = top_pwds[0][1]  if top_pwds  else 1

    def bar(count, total, width=18):
        filled = int(count / total * width)
        return f"[cyan]{'█' * filled}[/cyan][dim]{'░' * (width - filled)}[/dim]"

    tu = Table(title="[bold]Top Usernames[/bold]", box=box.SIMPLE_HEAD,
               header_style="bold cyan", title_style="bold white", padding=(0,1))
    tu.add_column("Username",  width=18)
    tu.add_column("Count",     width=8, justify="right")
    tu.add_column("Frequency", width=22)
    for username, count in top_users:
        tu.add_row(f"[yellow]{username}[/yellow]", str(count), bar(count, max_u))

    tp = Table(title="[bold]Top Passwords[/bold]", box=box.SIMPLE_HEAD,
               header_style="bold cyan", title_style="bold white", padding=(0,1))
    tp.add_column("Password",  width=18)
    tp.add_column("Count",     width=8, justify="right")
    tp.add_column("Frequency", width=22)
    for password, count in top_pwds:
        tp.add_row(f"[magenta]{password}[/magenta]", str(count), bar(count, max_p))

    console.print()
    console.print(Columns([tu, tp], equal=True, expand=True))
    console.print()


def cmd_timeline(events: list, hours: int = 12, buckets: int = 24):
    auth = [e for e in events if e.get("event") == "auth_attempt"]
    if not auth:
        console.print("[yellow]  No auth events found.[/yellow]")
        return

    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    bucket_size = timedelta(hours=hours) / buckets
    counts = [0] * buckets

    for e in auth:
        t = parse_time(e["logged_at"])
        idx = int((t - start) / bucket_size)
        if 0 <= idx < buckets:
            counts[idx] += 1

    max_count = max(counts) if counts else 1
    bar_height = 12
    width_per = 3

    console.print(f"\n  [bold]Attack Timeline — last {hours}h[/bold]   "
                  f"[dim](each column = {int(hours*60/buckets)}m, peak = {max_count:,} attempts)[/dim]\n")

    for row in range(bar_height, 0, -1):
        line = "  "
        threshold = max_count * row / bar_height
        for c in counts:
            if c >= threshold:
                intensity = c / max_count if max_count > 0 else 0
                if intensity > 0.75:   color = "[red]"
                elif intensity > 0.4:  color = "[yellow]"
                else:                  color = "[cyan]"
                line += f"{color}{'█' * width_per}[/]"
            else:
                line += "[dim]" + "·" * width_per + "[/dim]"
        if row == bar_height:
            line += f"  [dim]{max_count:,}[/dim]"
        console.print(line)

    # X axis labels
    label_line = "  "
    for i in range(0, buckets, buckets // 6):
        t = start + bucket_size * i
        label = t.strftime("%H:%M")
        label_line += label.ljust(width_per * (buckets // 6))
    console.print(f"[dim]{label_line}[/dim]\n")


def cmd_fingerprint(events: list):
    connect = [e for e in events if e.get("event") == "connect" and e.get("client_version")]
    if not connect:
        console.print("[yellow]  No client version data found.[/yellow]")
        return

    tool_counts: Counter = Counter()
    raw_counts:  Counter = Counter()

    for e in connect:
        cv = e["client_version"]
        raw_counts[cv] += 1
        tool_counts[fingerprint_tool(cv)] += 1

    t1 = Table(title="[bold]Attacker Tool Fingerprints[/bold]", box=box.SIMPLE_HEAD,
               header_style="bold cyan", title_style="bold white", padding=(0,1))
    t1.add_column("Tool / Library",    min_width=38)
    t1.add_column("Sessions",          width=10, justify="right")
    t1.add_column("% Share",           width=10, justify="right")

    total = sum(tool_counts.values())
    for tool, count in tool_counts.most_common():
        pct = count / total * 100
        t1.add_row(tool, str(count), f"{pct:.1f}%")

    t2 = Table(title="[bold]Raw Client Version Strings[/bold]", box=box.SIMPLE_HEAD,
               header_style="bold cyan", title_style="bold white", padding=(0,1))
    t2.add_column("Version String",    min_width=38)
    t2.add_column("Count",             width=8, justify="right")

    for cv, count in raw_counts.most_common(15):
        t2.add_row(f"[dim]{cv}[/dim]", str(count))

    console.print()
    console.print(t1)
    console.print()
    console.print(t2)
    console.print()


def cmd_hunt(events: list, ip: str):
    ip_events = [e for e in events if e.get("src_ip") == ip]
    if not ip_events:
        console.print(f"\n  [yellow]No events found for IP:[/yellow] [white]{ip}[/white]\n")
        return

    auth    = [e for e in ip_events if e.get("event") == "auth_attempt"]
    connect = [e for e in ip_events if e.get("event") == "connect" and e.get("client_version")]

    client = connect[0]["client_version"] if connect else "unknown"
    score, label = score_ip(len(auth), len(set(e.get("username","") for e in auth)),
                            len(set(e.get("password","") for e in auth)), client)

    console.print(f"\n  [bold white]IP Investigation:[/bold white] [cyan]{ip}[/cyan]\n")

    info = Table.grid(padding=(0, 4))
    info.add_column(style="dim", width=22)
    info.add_column(style="bold white")
    info.add_row("Threat score",     f"{score}/100  {label}")
    info.add_row("Tool fingerprint", fingerprint_tool(client))
    info.add_row("Client version",   f"[dim]{client}[/dim]")
    info.add_row("Total attempts",   f"[red]{len(auth):,}[/red]")
    info.add_row("Unique usernames", str(len(set(e.get("username","") for e in auth))))
    info.add_row("Unique passwords", str(len(set(e.get("password","") for e in auth))))
    if ip_events:
        times = sorted(parse_time(e["logged_at"]) for e in ip_events)
        info.add_row("First seen",   times[0].strftime("%Y-%m-%d %H:%M:%S UTC"))
        info.add_row("Last seen",    times[-1].strftime("%Y-%m-%d %H:%M:%S UTC"))
    console.print(info)

    if auth:
        console.print(f"\n  [bold]Credential pairs tried:[/bold]")
        sample = Table(box=box.SIMPLE, padding=(0,2), show_header=True,
                       header_style="bold cyan")
        sample.add_column("Username", width=18)
        sample.add_column("Password", width=20)
        sample.add_column("Time",     width=22, style="dim")
        for e in auth[:25]:
            sample.add_row(
                e.get("username","?"),
                e.get("password","?"),
                e.get("logged_at","")[:19],
            )
        console.print(sample)
    console.print()


def cmd_report_html(events: list) -> Path:
    auth    = [e for e in events if e.get("event") == "auth_attempt"]
    connect = [e for e in events if e.get("event") == "connect"]
    unique_ips = set(e["src_ip"] for e in events if "src_ip" in e)

    ip_attempts = Counter(e["src_ip"] for e in auth if "src_ip" in e)
    top_ips = ip_attempts.most_common(10)
    top_users = Counter(e["username"] for e in auth if "username" in e).most_common(10)
    top_pwds  = Counter(e["password"] for e in auth if "password" in e).most_common(10)

    ip_client = {}
    for e in connect:
        ip = e.get("src_ip","")
        cv = e.get("client_version","")
        if cv and ip not in ip_client:
            ip_client[ip] = cv

    def rows(items):
        return "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k,v in items)

    def threat_badge(ip):
        auth_e = [e for e in auth if e.get("src_ip") == ip]
        s, _ = score_ip(len(auth_e), len(set(e.get("username","") for e in auth_e)),
                         len(set(e.get("password","") for e in auth_e)), ip_client.get(ip,""))
        if s >= 75: return f'<span class="badge critical">CRITICAL</span>'
        if s >= 50: return f'<span class="badge high">HIGH</span>'
        if s >= 25: return f'<span class="badge medium">MEDIUM</span>'
        return f'<span class="badge low">LOW</span>'

    ip_table_rows = "".join(
        f"<tr><td>{ip}</td><td>{cnt}</td><td>{fingerprint_tool(ip_client.get(ip,''))}</td><td>{threat_badge(ip)}</td></tr>"
        for ip, cnt in top_ips
    )

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ThreatLens Report — {ts}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;500;600&display=swap');
  :root {{
    --bg: #0d1117; --surface: #161b22; --surface2: #1e2530;
    --border: #30363d; --text: #e6edf3; --muted: #8b949e;
    --red: #ff4444; --yellow: #f0a500; --cyan: #58d7f7; --green: #3fb950;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; padding: 2rem; }}
  h1 {{ font-family: 'JetBrains Mono', monospace; font-size: 1.4rem; color: var(--cyan); margin-bottom: 0.25rem; }}
  .subtitle {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 2rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }}
  .stat-label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  .stat-value {{ font-size: 1.8rem; font-weight: 600; font-family: 'JetBrains Mono', monospace; margin-top: 0.25rem; }}
  .red {{ color: var(--red); }} .yellow {{ color: var(--yellow); }} .cyan {{ color: var(--cyan); }}
  section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; }}
  section h2 {{ font-size: 0.95rem; font-weight: 600; margin-bottom: 1rem; color: var(--cyan); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  th {{ text-align: left; padding: 0.5rem 0.75rem; color: var(--muted); border-bottom: 1px solid var(--border); font-weight: 500; }}
  td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid #1e2530; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: var(--surface2); }}
  .badge {{ font-size: 0.7rem; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-family: 'Inter', sans-serif; }}
  .critical {{ background: #3d0000; color: #ff4444; }}
  .high {{ background: #2d1a00; color: #f0a500; }}
  .medium {{ background: #002d3d; color: #58d7f7; }}
  .low {{ background: #1e2530; color: #8b949e; }}
  .footer {{ color: var(--muted); font-size: 0.75rem; text-align: center; margin-top: 2rem; }}
</style>
</head>
<body>
<h1>⬡ ThreatLens SSH Honeypot Report</h1>
<p class="subtitle">Generated {ts} · ThreatLens v1.0</p>

<div class="grid">
  <div class="stat"><div class="stat-label">Auth Attempts</div><div class="stat-value red">{len(auth):,}</div></div>
  <div class="stat"><div class="stat-label">Unique IPs</div><div class="stat-value yellow">{len(unique_ips):,}</div></div>
  <div class="stat"><div class="stat-label">Sessions</div><div class="stat-value">{len(connect):,}</div></div>
  <div class="stat"><div class="stat-label">Unique Usernames</div><div class="stat-value cyan">{len(set(e.get('username','') for e in auth)):,}</div></div>
  <div class="stat"><div class="stat-label">Unique Passwords</div><div class="stat-value cyan">{len(set(e.get('password','') for e in auth)):,}</div></div>
</div>

<section>
  <h2>Top Attacking IPs</h2>
  <table>
    <tr><th>IP Address</th><th>Attempts</th><th>Tool</th><th>Threat</th></tr>
    {ip_table_rows}
  </table>
</section>

<section>
  <h2>Top Usernames Tried</h2>
  <table><tr><th>Username</th><th>Count</th></tr>{rows(top_users)}</table>
</section>

<section>
  <h2>Top Passwords Tried</h2>
  <table><tr><th>Password</th><th>Count</th></tr>{rows(top_pwds)}</table>
</section>

<p class="footer">ThreatLens · SSH Honeypot Analyzer · Educational Use Only</p>
</body>
</html>"""

    out = REPORT_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    out.write_text(html,encoding="utf-8")
    return out


def cmd_live(interval: int = 2):
    console.print("\n  [bold cyan]Live Monitor[/bold cyan] [dim]— watching for new attacks (Ctrl+C to stop)[/dim]\n")
    seen = set()

    if LOG_FILE.exists():
        with open(LOG_FILE) as f:
            for line in f:
                seen.add(line.strip())

    try:
        while True:
            time.sleep(interval)
            if not LOG_FILE.exists():
                continue
            with open(LOG_FILE) as f:
                lines = f.readlines()
            for line in lines:
                line = line.strip()
                if line and line not in seen:
                    seen.add(line)
                    try:
                        e = json.loads(line)
                        ts   = e.get("logged_at","")[:19]
                        ip   = e.get("src_ip","?")
                        evt  = e.get("event","?")
                        if evt == "auth_attempt":
                            u = e.get("username","?")
                            p = e.get("password","?")
                            console.print(f"  [dim]{ts}[/dim]  [red]AUTH[/red]  {ip:>16}  [yellow]{u}[/yellow] / [magenta]{p}[/magenta]")
                        elif evt == "connect":
                            cv = e.get("client_version","")[:45]
                            console.print(f"  [dim]{ts}[/dim]  [cyan]CONN[/cyan]  {ip:>16}  [dim]{cv}[/dim]")
                    except Exception:
                        pass
    except KeyboardInterrupt:
        console.print("\n  [dim]Live monitor stopped.[/dim]\n")


# ── CLI entrypoint ────────────────────────────────────────────────────────────

def print_banner():
    console.print(f"[cyan]{BANNER}[/cyan]")
    console.print("  [dim]SSH Honeypot Analyzer  ·  v1.0  ·  Educational Use Only[/dim]\n")


def main():
    parser = argparse.ArgumentParser(
        prog="threatlens",
        description="ThreatLens — SSH Honeypot Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  summary          Overall attack statistics
  top-ips          Ranked attacker IPs with threat scores
  top-creds        Most-tried usernames and passwords
  timeline         ASCII bar chart of attack frequency over time
  fingerprint      Identify attacker tools by SSH client version
  hunt             Deep-dive investigation of a single IP
  report           Export HTML report
  live             Real-time attack feed
        """
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("summary",     help="Overall attack statistics")
    p_ips = sub.add_parser("top-ips",    help="Top attacking IPs with threat scoring")
    p_ips.add_argument("--limit", type=int, default=15)

    sub.add_parser("top-creds",   help="Most-tried usernames and passwords")

    p_tl = sub.add_parser("timeline",    help="Attack frequency chart")
    p_tl.add_argument("--hours",   type=int, default=12)
    p_tl.add_argument("--buckets", type=int, default=24)

    sub.add_parser("fingerprint", help="Attacker tool fingerprinting")

    p_hunt = sub.add_parser("hunt",    help="Investigate a specific IP")
    p_hunt.add_argument("--ip", required=True, help="IP address to investigate")

    p_rep = sub.add_parser("report",   help="Export report")
    p_rep.add_argument("--format", choices=["html"], default="html")

    p_live = sub.add_parser("live",    help="Real-time attack monitor")
    p_live.add_argument("--interval", type=int, default=2)

    args = parser.parse_args()

    print_banner()

    if not args.command:
        parser.print_help()
        return

    events = load_events()

    if args.command == "summary":
        cmd_summary(events)
    elif args.command == "top-ips":
        cmd_top_ips(events, args.limit)
    elif args.command == "top-creds":
        cmd_top_creds(events)
    elif args.command == "timeline":
        cmd_timeline(events, args.hours, args.buckets)
    elif args.command == "fingerprint":
        cmd_fingerprint(events)
    elif args.command == "hunt":
        cmd_hunt(events, args.ip)
    elif args.command == "report":
        out = cmd_report_html(events)
        console.print(f"  [green]✓[/green] Report saved to [bold]{out}[/bold]\n")
    elif args.command == "live":
        cmd_live(args.interval)


if __name__ == "__main__":
    main()
