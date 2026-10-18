"""CLI entry point: python -m soc_autopilot.cli --logs ... --rules ... --out ..."""

from __future__ import annotations

import argparse

from .alerter import print_summary, write_jsonl
from .ingest import load_events
from .matcher import load_rules, run_rules


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="soc_autopilot", description="Sigma-lite detection pipeline")
    ap.add_argument("--logs", nargs="+", required=True, help="auth.log and/or .jsonl files")
    ap.add_argument("--rules", required=True, help="directory of *.yml rules")
    ap.add_argument("--out", default="alerts.jsonl", help="JSONL alert output path")
    args = ap.parse_args(argv)

    events = load_events(args.logs)
    rules = load_rules(args.rules)
    alerts = run_rules(events, rules)

    print(f"Loaded {len(events)} events, {len(rules)} rules.")
    print_summary(alerts)
    n = write_jsonl(alerts, args.out)
    print(f"\nWrote {n} alerts to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
