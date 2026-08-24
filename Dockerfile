ARG RESTIC_AGE_KEY_VERSION=1.2.1
ARG AGE_VERSION=1.3.1


FROM golang:1.27.0-alpine3.23@sha256:3747dcba41c8b0db3211fda4db61638b980e17ac5bb3c94460a975a9cfe19395 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -mod=readonly -ldflags="-s -w" -o restic-exporter .


FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS tools

ARG RESTIC_AGE_KEY_VERSION
ARG AGE_VERSION
ARG TARGETARCH

RUN apk add --no-cache curl

WORKDIR /out

RUN set -o errexit; \
    curl --fail --silent --show-error --location --output age.tar.gz \
      "https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/age-v${AGE_VERSION}-linux-${TARGETARCH}.tar.gz"; \
    tar --extract --gzip --file age.tar.gz --strip-components=1 --directory . age/age; \
    chmod 0755 age; \
    rm age.tar.gz

RUN set -o errexit; \
    curl --fail --silent --show-error --location --output restic-age-key.tar.gz \
      "https://github.com/josh/restic-age-key/releases/download/v${RESTIC_AGE_KEY_VERSION}/restic-age-key-v${RESTIC_AGE_KEY_VERSION}-linux-${TARGETARCH}.tar.gz"; \
    tar --extract --gzip --file restic-age-key.tar.gz --strip-components=1 --directory . restic-age-key/restic-age-key; \
    chmod 0755 restic-age-key; \
    rm restic-age-key.tar.gz

RUN mkdir cache


FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /src/restic-exporter /usr/local/bin/
COPY --from=tools /out/restic-age-key /usr/local/bin/
COPY --from=tools /out/age /usr/local/bin/
COPY --from=tools --chown=65534:65534 /out/cache /cache

LABEL org.opencontainers.image.title="restic-exporter"
LABEL org.opencontainers.image.description="Prometheus exporter for restic repositories"
LABEL org.opencontainers.image.source="https://github.com/josh/restic-exporter"
LABEL org.opencontainers.image.licenses="MIT"

ENV RESTIC_CACHE_DIR=/cache
USER 65534:65534

ENTRYPOINT ["restic-exporter"]
