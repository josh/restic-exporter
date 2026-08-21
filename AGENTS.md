# Agents Guide

This project is written in Go and uses Go modules for dependency management. The repository assumes Go 1.25 or newer.

## Architecture

This is a single-file project (`main.go`). It works as follows:

1. **Config** — `loadConfig()` reads environment variables, then `main()` applies CLI flag overrides.
2. **Restic as a library** — `openRepository()` builds `global.Options` from the standard `RESTIC_*` environment variables and opens the repository through `github.com/josh/restic-api` (a fork of restic with `internal/` exposed as `api/`; code exists only on tags, pin exactly). `getSnapshots()`, `getGlobalStats()`, and `getLocks()` read repository data in-process — no restic binary is involved anywhere, and the exporter never takes a repository lock. `getGlobalStats()` is a port of `restic stats --mode raw-data` from upstream `cmd/restic/cmd_stats.go`, which is not importable.
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

Running this project requires a real restic repository and credentials (`RESTIC_REPOSITORY` or `RESTIC_REPOSITORY_FILE`, plus one of `RESTIC_PASSWORD`, `RESTIC_PASSWORD_FILE`, or `RESTIC_PASSWORD_COMMAND`). There is no mock or stub mode, but the test suite creates throwaway local repositories, so `go test` covers most changes.

## Testing

Run `go test ./...`. Tests live in `main_test.go` and create real local restic repositories in temp directories using the restic-api library itself (`global.CreateRepository` plus the archiver) — no restic binary or network access is required. Ambient `RESTIC_*` environment variables are cleared by `clearResticEnv` so a developer's own restic config cannot leak into tests.

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
