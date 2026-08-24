---
name: rebase
description: Check upstream restic-exporter for metric, label, or env var changes and report differences.
disable-model-invocation: false
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

## Output

Report the differences only. Do not make changes. Organize the report as:

1. **New upstream metrics/labels** — metrics or labels present upstream but missing here.
2. **Removed upstream metrics/labels** — metrics or labels we have that upstream has dropped.
3. **Changed definitions** — mismatches in metric type, help string, or label names.
4. **New or changed env vars** — environment variables added, removed, or given new defaults upstream.
5. **No differences** — if everything matches, say so.

## Reference files

- **Upstream metrics and labels** are all defined in `exporter/exporter.py` in the upstream repo.
- **Target Grafana dashboard** is `grafana/grafana_dashboard.json` in the upstream repo. Metric names and labels must match for it to work.
- **Our Grafana dashboard** is `grafana/restic-exporter.json`. It began as a copy of the upstream file but is now an intentional fork — see below. Compare the two with `jq -S`, not raw `diff`: our copy is Prettier-formatted, so a plain diff is all noise.

## Intentional divergences from upstream

These differences are by design and should **not** be reported as discrepancies:

- **CLI flags**: This project accepts `--listen-port`, `--listen-address`, `--refresh-interval`, `--include-paths`, and `--version` as command-line flags. Upstream is env-var-only.
- **systemd socket activation**: This project supports `LISTEN_PID`, `LISTEN_FDS`, and `LISTEN_FDNAMES` for systemd socket activation. These are Go-specific and have no upstream equivalent.
- **Default port**: Go uses `9183` instead of upstream's `8001` — 8001 is too common a port.
- **Default listen address**: Go uses `[::]` (IPv6 dual-stack) instead of upstream's `0.0.0.0` (IPv4 only) — better dual-stack support.
- **Env var prefix**: Go uses `RESTIC_EXPORTER_` prefix on all exporter-specific env vars (e.g. `RESTIC_EXPORTER_LISTEN_PORT` instead of upstream's `LISTEN_PORT`) to avoid conflicts with other software.
- **Grafana dashboard**: `grafana/restic-exporter.json` is no longer a mirror of upstream's `grafana_dashboard.json`. It intentionally drops the `Repository Check` panel (we do not export `restic_check_success`), adds `Exporter Health` and `Repository Stale Locks` panels, and adds `datasource` and `instance` template variables so one dashboard can serve several exporters. The repository selector unions successful exporters with `up{job="restic-exporter"}` so a ServiceMonitor target remains selectable before its first successful refresh. Summary stats are instant `max(...)` queries limited to targets where `up == 1`, while the health panel uses `up` because this exporter returns 503 after a failed repository refresh. Backup tables join on `snapshot_hash`, expose the labels that distinguish backup identities, and put the stalest backup first. The dashboard refreshes every five minutes, uses step interpolation for snapshot gauges, aggregates the size pie by hostname, standardizes decimal-byte units, and keeps a consolidated Advanced row collapsed by default. It also calls `restic_scrape_duration_seconds` repository collection duration because the metric measures the in-process repository refresh rather than a Prometheus HTTP scrape. Do **not** wholesale-copy the upstream dashboard over it — that already happened once in `69a2dfa` and silently reverted the panel removal from `e449fdf`. Port individual upstream panel changes instead.
- **HTTP endpoints**: upstream serves only `/metrics`, always with a 200 — `collect()` yields nothing until the first refresh lands and keeps serving the previous values after a failed one. This project adds `/healthz` and `/readyz`, and returns 503 from `/metrics` and `/readyz` until a refresh has succeeded, so a scrape never records values from a refresh that could not read the repository. Upstream's equivalent knob is `EXIT_ON_ERROR`, which exits the process instead.
- **Additional metrics**: `restic_stale_locks_total` has no upstream equivalent. It is additive — no upstream metric is renamed, removed, or relabelled — so upstream dashboards and alert rules are unaffected. `restic_locks_total` stays unchanged for compatibility.
- **Implementation details**: Concurrency model, error handling, JSON parsing, and code structure are all intentionally different. Only the Prometheus output and env var interface need to match.
