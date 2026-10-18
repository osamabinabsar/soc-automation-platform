"""Sigma-lite rule engine.

Supports the small rule subset documented in the README:
  selection:   dict of field -> value | list | "!value" | modifiers (contains, re)
  timeframe:   "5m" / "30s" / "2h" (aggregation rules)
  condition:   "selection"  or  "selection | count() by <field> > <n>"
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import yaml

_TIMEFRAME = re.compile(r"^(\d+)([smhd])$")
_COND_AGG = re.compile(
    r"^(?P<sel>\w+)\s*\|\s*count\(\)\s+by\s+(?P<group>\w+)\s*>\s*(?P<th>\d+)$"
)
_UNIT_SECS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_timeframe(tf: str) -> timedelta:
    m = _TIMEFRAME.match(tf.strip())
    if not m:
        raise ValueError(f"bad timeframe: {tf!r}")
    return timedelta(seconds=int(m.group(1)) * _UNIT_SECS[m.group(2)])


@dataclass
class Rule:
    title: str
    id: str
    logsource: str
    level: str
    selection: dict
    timeframe: timedelta | None = None
    group_by: str | None = None
    threshold: int | None = None
    description: str = ""
    mitre: str = ""
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        det = d["detection"]
        selection = det["selection"]
        timeframe = parse_timeframe(det["timeframe"]) if "timeframe" in det else None
        group_by = threshold = None
        cond = det["condition"].strip()
        if cond.startswith("selection"):
            agg = _COND_AGG.match(cond)
            if agg:
                if agg["sel"] != "selection":
                    raise ValueError(f"condition references unknown selection {agg['sel']!r}")
                group_by, threshold = agg["group"], int(agg["th"])
            elif cond != "selection":
                raise ValueError(f"unsupported condition: {cond!r}")
        else:
            raise ValueError(f"unsupported condition: {cond!r}")
        return cls(
            title=d["title"],
            id=d["id"],
            logsource=d.get("logsource", ""),
            level=d.get("level", "medium"),
            selection=selection,
            timeframe=timeframe,
            group_by=group_by,
            threshold=threshold,
            description=d.get("description", ""),
            mitre=d.get("mitre", ""),
            raw=d,
        )

    @property
    def is_aggregation(self) -> bool:
        return self.group_by is not None


def load_rules(rules_dir: str | Path) -> list[Rule]:
    rules = []
    for yml in sorted(Path(rules_dir).glob("*.yml")):
        with yml.open(encoding="utf-8") as fh:
            rules.append(Rule.from_dict(yaml.safe_load(fh)))
    return rules


def _match_value(event_val, rule_val) -> bool:
    """Compare one (possibly modified) event field against a rule value."""
    if isinstance(rule_val, list):
        return any(_match_value(event_val, v) for v in rule_val)
    if not isinstance(rule_val, str) or "|" in "":
        pass  # non-string scalar comparison falls through to equality
    if isinstance(rule_val, str) and rule_val.startswith("!"):
        return str(event_val) != rule_val[1:]
    if event_val is None:
        return False
    return str(event_val) == str(rule_val)


def _match_field(event: dict, key: str, rule_val) -> bool:
    field_name, _, modifier = key.partition("|")
    event_val = event.get(field_name)
    if modifier == "contains":
        if isinstance(rule_val, list):
            return any(_contains(event_val, v) for v in rule_val)
        return _contains(event_val, rule_val)
    if modifier == "re":
        if event_val is None:
            return False
        return re.search(str(rule_val), str(event_val)) is not None
    return _match_value(event_val, rule_val)


def _contains(event_val, needle) -> bool:
    if event_val is None:
        return False
    if isinstance(needle, str) and needle.startswith("!"):
        return needle[1:].lower() not in str(event_val).lower()
    return str(needle).lower() in str(event_val).lower()


def matches(event: dict, rule: Rule) -> bool:
    """True when every key in the rule selection matches the event.

    Note: `logsource` is metadata (routing hint in real Sigma), NOT a filter —
    the selections themselves carry event_type/component fields where needed.
    """
    return all(_match_field(event, k, v) for k, v in rule.selection.items())


@dataclass
class Alert:
    rule_id: str
    rule_title: str
    level: str
    mitre: str
    ts: datetime
    group: str | None
    count: int
    sample: dict

    def as_dict(self) -> dict:
        sample = {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in self.sample.items()}
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "level": self.level,
            "mitre": self.mitre,
            "ts": self.ts.isoformat(),
            "group": self.group,
            "count": self.count,
            "sample": sample,
        }


def run_rules(events: list[dict], rules: list[Rule]) -> list[Alert]:
    """Evaluate all rules against events, returning alerts sorted by time."""
    alerts: list[Alert] = []
    for rule in rules:
        if rule.is_aggregation:
            alerts.extend(_run_aggregation(events, rule))
        else:
            alerts.extend(_run_match(events, rule))
    alerts.sort(key=lambda a: a.ts)
    return alerts


def _run_match(events: list[dict], rule: Rule) -> list[Alert]:
    out = []
    for ev in events:
        if matches(ev, rule):
            out.append(
                Alert(rule.id, rule.title, rule.level, rule.mitre, ev["ts"], None, 1, ev)
            )
    return out


def _run_aggregation(events: list[dict], rule: Rule) -> list[Alert]:
    """Sliding-window count per group field; one alert per burst."""
    assert rule.group_by and rule.threshold and rule.timeframe
    groups: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        if matches(ev, rule):
            groups[str(ev.get(rule.group_by, "-"))].append(ev)

    out: list[Alert] = []
    for group_val, gevs in groups.items():
        gevs.sort(key=lambda e: e["ts"])
        window: deque[dict] = deque()
        firing = False
        for ev in gevs:
            window.append(ev)
            cutoff = ev["ts"] - rule.timeframe
            while window and window[0]["ts"] < cutoff:
                window.popleft()
            if len(window) > rule.threshold:
                if not firing:
                    out.append(
                        Alert(
                            rule.id,
                            rule.title,
                            rule.level,
                            rule.mitre,
                            ev["ts"],
                            group_val,
                            len(window),
                            window[0],
                        )
                    )
                    firing = True
            else:
                firing = False
    return out
