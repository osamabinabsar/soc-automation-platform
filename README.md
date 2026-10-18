# SOC Automation Platform

Automated detection pipeline: log ingestion → Sigma-lite rule matching → alerting.
Built as the engine behind a home SOC lab — no external SIEM required to run the demo.

**Stack:** Python, YAML detection rules (Sigma-inspired schema), JSONL alert output.

## How it works

```
samples/logs/*  ──▶  ingest.py   ──▶  matcher.py   ──▶  alerter.py
 (syslog/JSONL)     (parse+normalise)  (match + aggregate)  (console + alerts.jsonl)
```

- **Ingestion** normalises Linux syslog (`/var/log/auth.log` style) and JSONL event
  streams into one event shape: `{ts, source, ...fields}`.
- **Rules** live in `sigma_rules/` as YAML. They follow a deliberately small subset of
  the Sigma schema (documented below) so the engine stays readable and dependency-light.
- **Alerting** emits one JSONL record per detection and a console summary.

## Sigma-lite schema

```yaml
title: SSH Brute Force - repeated failures from one source
id: <uuid>
logsource: linux-auth          # which ingestor produces matching events
level: high                    # low | medium | high | critical
detection:
  selection:                   # all key:value pairs must match (AND)
    action: failed_password    # exact match
    component: sudo
    action|contains: failure   # substring modifier
    path|re: '(?i)union\s'     # regex modifier
    user: '!root'              # negation
    src_ip:                    # list = OR
      - 10.0.0.1
      - 10.0.0.2
  timeframe: 5m                # optional, aggregation rules only
  condition: selection | count() by src_ip > 10
```

Two rule shapes are supported:

1. **Match rules** — `condition: selection` fires per matching event.
2. **Aggregation rules** — `condition: selection | count() by <field> > <n>`
   fires once per group when the count of matching events inside the sliding
   `timeframe` window exceeds the threshold.

This is a Sigma-*inspired* schema, not a full Sigma implementation; the engine is
~200 lines so you can read and adapt it to your SIEM of choice.

## Quick start

```bash
pip install -r requirements.txt
python -m soc_autopilot.cli \
  --logs samples/logs/auth.log samples/logs/events.jsonl \
  --rules sigma_rules \
  --out alerts.jsonl
```

Expected output: a handful of alerts covering SSH brute force, invalid-user
enumeration, sudo failures, DNS tunnelling, SQL injection probes and encoded
PowerShell — the synthetic sample logs contain exactly those attacks.

## Tests

```bash
pytest -q
```

## Project layout

```
soc_autopilot/      engine package (ingest, match, alert, cli)
sigma_rules/        6 detection rules
samples/logs/       synthetic logs (auth.log + JSONL), no real data
tests/              pytest suite
```

## Notes

- All sample data is synthetic. No production logs or client data are included.
- Detection content maps to MITRE ATT&CK techniques noted in each rule file.
- Written to be portable: the matcher consumes plain dicts, so wiring it to
  Elasticsearch, Wazuh or Splunk is an adapter away.
