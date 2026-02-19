# Agents Guide

This project is written in Go and uses Go modules for dependency management. The repository assumes Go 1.25 or newer.

## Architecture

This is a single-file project (`main.go`). It works as follows:

1. **Config** — `loadConfig()` reads environment variables, then `main()` applies CLI flag overrides.
2. **Restic subprocess** — functions like `getSnapshots()`, `getGlobalStats()`, and `getLocks()` shell out to the `restic` binary and parse its JSON output.
3. **Metric collection** — `updateResticMetrics()` calls the restic functions, deduplicates snapshots by hash, and sets Prometheus gauge values.
4. **Refresh loop** — a background goroutine runs `updateResticMetrics()` immediately on startup, then on a timer (default 3600s). Metrics are **not** collected on each HTTP scrape.
5. **Generate mode** — when `--output` is set, collects metrics once and exits. Output can be a file path (for node_exporter textfile collector), `-` for stdout, or an HTTP(S) URL to POST metrics to (e.g. Prometheus push/import endpoint).
6. **HTTP server** — starts listening immediately. Returns 503 until the first collection completes, then serves `/metrics` using the Prometheus client library with a custom registry.

All Prometheus metrics are declared as package-level `var`s and registered in `init()`.

## Setup

1. Install Go 1.25 or later.
2. Download dependencies with:

```sh
go mod download
```

## Local development

Running this project requires a real restic repository and credentials (`RESTIC_REPOSITORY` plus one of `RESTIC_PASSWORD`, `RESTIC_PASSWORD_FILE`, or `RESTIC_PASSWORD_COMMAND`). There is no mock or stub mode. Changes are typically verified via build and static analysis only.

## Testing

No test suite available. That's okay! Please do not add one.

## Pre-commit checklist

Run these before committing:

```sh
go fmt ./...
go vet ./...
go build ./...
```

All three must pass with no errors and no formatting changes.

## Building

The `version` variable in `main.go` is updated manually each release. It can also be overridden at build time via `-ldflags` to include more specific information like the current git tag:

```sh
go build -ldflags "-X main.version=$(git describe --tags)" ./...
```

## Comments

Keep comments concise. Only add them when they clarify non-obvious logic.

## Rebase

See `.claude/skills/rebase/SKILL.md`.
