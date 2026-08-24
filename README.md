# restic-exporter

Prometheus exporter for Restic repositories — a Go reimplementation of [ngosang/restic-exporter](https://github.com/ngosang/restic-exporter).

This project exports the same Prometheus metrics as the original Python-based exporter and is designed as a drop-in replacement. Existing [Grafana dashboards](https://github.com/ngosang/restic-exporter/tree/main/grafana) from the upstream project are fully compatible.

## Motivation

The original [ngosang/restic-exporter](https://github.com/ngosang/restic-exporter) is an excellent project. This rewrite targets environments where a single static Go binary is preferred over a Python runtime.

Additional features not in the upstream project:

- **Oneshot mode**: Write metrics to stdout, a file, or POST to a URL and exit immediately — useful for cron jobs, systemd timers, or CI pipelines without running a persistent server.
- **CLI flags**: All configuration options are available as both environment variables and CLI flags.
- **Stale lock detection**: `restic_stale_locks_total` counts locks restic considers stale — older than its own 30 minute stale lock timeout, or owned by a process that no longer exists on the exporter host.

## Requirements

- Go 1.25+ (for building)

## Usage

```
./restic-exporter [flags]
```

Metrics are served at `http://[::]:9183/metrics` by default.

### Oneshot mode

Instead of running a persistent HTTP server, you can collect metrics once and output them immediately:

```sh
# Write to stdout
./restic-exporter -output -

# Write to a file (compatible with node_exporter textfile collector)
./restic-exporter -output /var/lib/prometheus/node-exporter/restic.prom

# POST to a Prometheus push/import endpoint
./restic-exporter -output http://prometheus:9090/api/v1/import/prometheus
```

## Docker

Multi-arch images (`linux/amd64`, `linux/arm64`) are published to `ghcr.io/josh/restic-exporter`, tagged with the release version and `latest`:

```sh
docker run --rm -p 9183:9183 \
  -e RESTIC_REPOSITORY=s3:s3.amazonaws.com/bucket/repo \
  -e RESTIC_PASSWORD=... \
  -e AWS_ACCESS_KEY_ID=... \
  -e AWS_SECRET_ACCESS_KEY=... \
  ghcr.io/josh/restic-exporter
```

The image runs as an unprivileged user and keeps the restic cache in `/cache`; mount a volume there to keep it across restarts.

## Configuration

Configuration comes from environment variables and can be overridden by CLI flags.

### Required environment variables

- `RESTIC_REPOSITORY` or `RESTIC_REPOSITORY_FILE`
- `RESTIC_PASSWORD` or `RESTIC_PASSWORD_FILE` or `RESTIC_PASSWORD_COMMAND`

### Optional environment variables

- `RESTIC_EXPORTER_REFRESH_INTERVAL` (seconds, default: `3600`)
- `RESTIC_EXPORTER_LISTEN_ADDRESS` (default: `[::]`)
- `RESTIC_EXPORTER_LISTEN_PORT` (default: `9183`)
- `RESTIC_EXPORTER_INCLUDE_PATHS` (default: `false`)

The following standard restic environment variables are also honored: `RESTIC_KEY_HINT`, `RESTIC_CACHE_DIR`, `RESTIC_CACERT`, `RESTIC_TLS_CLIENT_CERT`, `RESTIC_HTTP_USER_AGENT`, and all backend-specific credentials (`AWS_*`, `B2_*`, `AZURE_*`, `GOOGLE_*`, `RESTIC_REST_*`, ...).
### CLI flags

- `-verbose` (enable debug logging)
- `-refresh-interval` (seconds between metric refreshes)
- `-listen-address`
- `-listen-port`
- `-include-paths`
- `-output` (write metrics to file/stdout/URL and exit)

## Differences from ngosang/restic-exporter

| Feature                                  | ngosang/restic-exporter | this project                                   |
| ---------------------------------------- | ----------------------- | ---------------------------------------------- |
| Language                                 | Python                  | Go                                             |
| Environment variable names               | unprefixed              | prefixed with `RESTIC_EXPORTER_`               |
| `NO_CHECK`, `NO_STATS`, `NO_LOCKS` flags | supported               | removed (stats and locks are always collected) |
| CLI flags                                | not available           | available for all options                      |
| Oneshot output mode                      | not available           | `-output` flag                                 |
| Docker image                             | available               | available                                      |

## systemd

There is a sample unit file under `systemd/` you can adapt for your environment.

Example:

```
[Unit]
Description=restic-exporter
After=network-online.target

[Service]
ExecStart=/usr/local/bin/restic-exporter -listen-address="[::]" -listen-port=9183
Environment=RESTIC_REPOSITORY=...
Environment=RESTIC_PASSWORD=...
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Helm

The chart in [`charts/restic-exporter`](charts/restic-exporter) runs the exporter as a Deployment with a ClusterIP Service, plus an optional ServiceMonitor and NetworkPolicies. Each release monitors one repository, so install it once per repository.

Create a Secret holding `RESTIC_PASSWORD` and any backend credentials — the chart only references existing Secrets:

```sh
kubectl create secret generic home-restic \
  --from-literal=RESTIC_PASSWORD=... \
  --from-literal=AWS_ACCESS_KEY_ID=... \
  --from-literal=AWS_SECRET_ACCESS_KEY=...
```

Then install:

```sh
helm upgrade --install home ./charts/restic-exporter \
  --set restic.repository=s3:s3.amazonaws.com/bucket/home \
  --set restic.existingSecret=home-restic \
  --set prometheusScrape=false \
  --set serviceMonitor.enabled=true
```

`prometheusScrape` adds `prometheus.io/scrape` and `prometheus.io/port` pod annotations for scrape jobs that discover targets by annotation. It is on by default; disable it when scraping by ServiceMonitor as above, or the target may be scraped twice. `serviceMonitor.enabled` requires the Prometheus Operator CRDs. By default, all chart releases share the Prometheus job `restic-exporter`, while the `instance` label is the release name (`home` above), so the [Grafana dashboard](grafana/restic-exporter.json) can switch between repositories. Set `serviceMonitor.jobLabel` to another Service label, or to an empty string to use the Operator's Service-name default. `networkPolicy.ingress` and `networkPolicy.egress` are off by default; see [`values.yaml`](charts/restic-exporter/values.yaml) for all options.

## Credits

Based on [ngosang/restic-exporter](https://github.com/ngosang/restic-exporter) by [@ngosang](https://github.com/ngosang). Metric names, labels, and exporter design originate from that project.
