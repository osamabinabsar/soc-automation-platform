"""Alert output: JSONL file + console summary."""

from __future__ import annotations

import json
from pathlib import Path

from .matcher import Alert

_COLORS = {"critical": "\033[91m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
_RESET = "\033[0m"


def write_jsonl(alerts: list[Alert], out_path: str | Path) -> int:
    path = Path(out_path)
    with path.open("w", encoding="utf-8") as fh:
        for a in alerts:
            fh.write(json.dumps(a.as_dict()) + "\n")
    return len(alerts)


def print_summary(alerts: list[Alert]) -> None:
    if not alerts:
        print("No alerts fired.")
        return
    print(f"{len(alerts)} alert(s):\n")
    for a in alerts:
        color = _COLORS.get(a.level, "")
        group = f"  group={a.group}  count={a.count}" if a.group else ""
        when = a.ts.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{color}[{a.level.upper():8}]{_RESET} {when}{group}")
        print(f"           {a.rule_title} ({a.rule_id})")
