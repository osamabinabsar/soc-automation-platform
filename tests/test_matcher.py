from datetime import datetime, timedelta
from pathlib import Path

from soc_autopilot.ingest import load_events
from soc_autopilot.matcher import load_rules, run_rules

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "logs"
RULES = Path(__file__).resolve().parent.parent / "sigma_rules"


def _fired(alerts, rule_id):
    return [a for a in alerts if a.rule_id == rule_id]


def test_sample_timeline_fires_expected_alerts():
    events = load_events([SAMPLES / "auth.log", SAMPLES / "events.jsonl"])
    rules = load_rules(RULES)
    alerts = run_rules(events, rules)

    brute = _fired(alerts, "5f2b1a40-1c11-4a5e-9f66-2f0a94f3e001")
    assert len(brute) == 1
    assert brute[0].group == "198.51.100.7"
    assert brute[0].count > 10

    assert _fired(alerts, "3a7c9d21-8b44-4c0a-bd1e-77a5c8f21002")  # invalid users
    assert _fired(alerts, "9d1e4b77-2f05-4e39-9c2a-6b8d0a5e3303")  # sudo failure
    assert len(_fired(alerts, "c0f3a2b8-6d91-4a7c-8e52-1b9f4d7a6604")) == 2  # DNS tunnelling
    assert len(_fired(alerts, "e5b7c3d9-1a02-4f68-b3d7-9c2e8f60aa05")) == 2  # SQLi
    assert len(_fired(alerts, "a8c2e6f0-4b33-4d95-9a1e-5d7b0c8e1106")) == 1  # encoded PS


def test_benign_events_do_not_alert():
    events = load_events([SAMPLES / "auth.log", SAMPLES / "events.jsonl"])
    rules = load_rules(RULES)
    alerts = run_rules(events, rules)
    # No aggregation alert for the quiet internal IP
    assert not [a for a in alerts if a.group == "10.0.0.12"]


def test_aggregation_window_respected():
    """>threshold failures spread beyond the window must not fire."""
    from soc_autopilot.matcher import Rule, run_rules

    rule = Rule.from_dict(
        {
            "title": "t",
            "id": "test-id",
            "logsource": "linux-auth",
            "level": "high",
            "detection": {
                "selection": {"action": "failed_password"},
                "timeframe": "5m",
                "condition": "selection | count() by src_ip > 10",
            },
        }
    )
    base = datetime(2026, 9, 22, 10, 0, 0)
    # 11 failures, one every 10 minutes -> never >10 inside 5m
    events = [
        {"ts": base + timedelta(minutes=10 * i), "source": "linux-auth",
         "action": "failed_password", "src_ip": "1.2.3.4"}
        for i in range(11)
    ]
    assert run_rules(events, [rule]) == []

    # 11 failures inside 4 minutes -> fires once
    events = [
        {"ts": base + timedelta(seconds=20 * i), "source": "linux-auth",
         "action": "failed_password", "src_ip": "1.2.3.4"}
        for i in range(11)
    ]
    alerts = run_rules(events, [rule])
    assert len(alerts) == 1
    assert alerts[0].count == 11
