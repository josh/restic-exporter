---
name: rebase
description: Guide for keeping Go port in sync with upstream restic-exporter metrics, labels, and env vars.
disable-model-invocation: true
context: fork
agent: Explore
---

# Rebase

This project is a Go port of [ngosang/restic-exporter](https://github.com/ngosang/restic-exporter), which is written in Python. The primary goal is metric compatibility — same metric names, labels, and environment variables — so existing Grafana dashboards and alerting rules work without modification.

## What to sync

- Prometheus metric names, types, and help strings
- Prometheus label names
- Environment variable names and default values

We do **not** need to match implementation details, code structure, or Python idioms. Only the public interface matters.

## How to review upstream

1. Fetch the upstream metric definitions:

```sh
gh api repos/ngosang/restic-exporter/contents/exporter/exporter.py --jq '.content' | base64 -d
```

2. Compare Prometheus metric definitions (names, types, help strings, labels) against our Go code.
3. Compare environment variable names and default values.
4. Check for any newly added or removed metrics or labels since the last review.

## Reference files

- **Upstream metrics and labels** are all defined in `exporter/exporter.py` in the upstream repo.
- **Target Grafana dashboard** is `grafana/grafana_dashboard.json` in the upstream repo. Metric names and labels must match for it to work.
