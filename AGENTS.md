# Agents Guide

This project is written in Go and uses Go modules for dependency management. The repository assumes Go 1.25 or newer.

## Setup

1. Install Go 1.25 or later.
2. Download dependencies with:

```sh
go mod download
```

## Testing

No test suite available. That's okay! Please do not add one.

## Formatting

Format code with:

```sh
go fmt ./...
```

## Code Quality

Run vet and static analysis tools before committing:

```sh
go vet ./...
```

Optionally run `golangci-lint` for additional checks:

```sh
golangci-lint run ./...
```

## Building

Build the project with:

```sh
go build ./...
```

## Comments

Keep comments concise. Only add them when they clarify non-obvious logic.

## Rebase

See `.claude/skills/rebase/SKILL.md`.
