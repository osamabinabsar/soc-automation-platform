"""Log ingestion: normalise Linux auth syslog lines and JSONL events.

Every event becomes a flat dict with at least:
    ts       -- timezone-naive datetime (parsed)
    source   -- "linux-auth" | "jsonl"
    raw      -- original line (for audit trail)
plus whatever fields the parser extracted (action, user, src_ip, ...).
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

_SYSLOG_TS = "%b %d %H:%M:%S"

# sshd messages we care about, in check order (invalid_user first: it also
# matches the "Failed password" shape).
_SSHD_PATTERNS = [
    (
        "invalid_user",
        re.compile(
            r"Failed password for invalid user (?P<user>\S+) "
            r"from (?P<ip>\S+) port (?P<port>\d+)"
        ),
    ),
    (
        "failed_password",
        re.compile(
            r"Failed password for (?:invalid user )?(?P<user>\S+) "
            r"from (?P<ip>\S+) port (?P<port>\d+)"
        ),
    ),
    (
        "accepted_password",
        re.compile(
            r"Accepted password for (?P<user>\S+) "
            r"from (?P<ip>\S+) port (?P<port>\d+)"
        ),
    ),
]

_SUDO_FAIL = re.compile(
    r"pam_unix\(sudo:auth\): authentication failure;.*?ruser=(?P<ruser>\S+).*?"
    r"user=(?P<user>\S+)",
    re.DOTALL,
)


def parse_auth_line(line: str, hostname: str = "host") -> dict | None:
    """Parse one auth.log line into an event dict, or None if uninteresting."""
    line = line.rstrip("\n")
    m = re.match(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$", line)
    if not m:
        return None
    ts_str, host, process, message = m.groups()
    try:
        # syslog has no year; assume current century window around now.
        year = datetime.now().year
        ts = datetime.strptime(f"{year} {ts_str}", "%Y " + _SYSLOG_TS)
    except ValueError:
        return None

    base = {"ts": ts, "source": "linux-auth", "host": host, "process": process.strip(), "raw": line}

    if "sshd" in process:
        for action, pat in _SSHD_PATTERNS:
            mm = pat.search(message)
            if mm:
                return {
                    **base,
                    "component": "sshd",
                    "action": action,
                    "user": mm["user"],
                    "src_ip": mm["ip"],
                    "src_port": int(mm["port"]),
                }
        return None

    if "sudo" in process or "sudo:" in message:
        mm = _SUDO_FAIL.search(message)
        if mm:
            return {
                **base,
                "component": "sudo",
                "action": "authentication failure",
                "user": mm["user"],
                "ruser": mm["ruser"],
                "src_ip": "-",
            }
    return None


def parse_jsonl_line(line: str) -> dict | None:
    """Parse one JSONL event. Requires an ISO 'ts' field."""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if "ts" not in obj:
        return None
    if isinstance(obj["ts"], str):
        obj["ts"] = datetime.fromisoformat(obj["ts"])
    obj.setdefault("source", "jsonl")
    obj["raw"] = line
    return obj


def load_events(paths: list[str | Path]) -> list[dict]:
    """Load and merge events from auth.log / .jsonl files, sorted by time."""
    events: list[dict] = []
    for p in paths:
        path = Path(p)
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                if path.suffix == ".jsonl":
                    ev = parse_jsonl_line(line)
                else:
                    ev = parse_auth_line(line)
                if ev is not None:
                    events.append(ev)
    events.sort(key=lambda e: e["ts"])
    return events
