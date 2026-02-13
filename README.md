# restic-exporter

Prometheus exporter for Restic repositories.

## Requirements

- Go 1.25+ (for building)
- `restic` available in `PATH`

## Usage

```
./restic-exporter [flags]
```

Metrics are served at `http://[::]:9183/metrics` by default.

## Configuration

Configuration comes from environment variables and can be overridden by CLI flags.

### Required environment variables

- `RESTIC_REPOSITORY`
- One of:
  - `RESTIC_PASSWORD`
  - `RESTIC_PASSWORD_FILE`
  - `RESTIC_PASSWORD_COMMAND`

### Optional environment variables

- `REFRESH_INTERVAL` (seconds, default: `3600`)
- `LISTEN_ADDRESS` (default: `[::]`)
- `LISTEN_PORT` (default: `9183`)
- `NO_CHECK` (default: `false`)
- `INCLUDE_PATHS` (default: `false`)

### CLI flags

- `-verbose` (enable debug logging)
- `-refresh-interval` (seconds between metric refreshes)
- `-listen-address`
- `-listen-port`
- `-no-check`
- `-include-paths`

Global stats and locks are always collected and no longer have disable flags.

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

## Grafana dashboards (upstream)

```
https://github.com/ngosang/restic-exporter/tree/main/grafana
```
