ARG RESTIC_AGE_KEY_VERSION=1.2.1
ARG AGE_VERSION=1.3.2


FROM golang:1.27.3-alpine3.23@sha256:8a5046497cda39860b832ffdbe8dd66018a0f05bb01352f533a36e7e2ced66a0 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -mod=readonly -ldflags="-s -w" -o restic-exporter .


FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS tools

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
