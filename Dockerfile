# ---- Builder ----
FROM golang:1.27.2-alpine@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS builder

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

RUN apk add --no-cache ca-certificates tzdata
RUN mkdir -p /data

WORKDIR /build

# Download dependencies first (cached as a separate layer).
COPY go.mod go.sum ./
RUN go mod download

# Build the binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux \
    go build \
    -ldflags="-s -w \
              -X main.version=${VERSION} \
              -X main.commit=${COMMIT} \
              -X main.date=${BUILD_DATE}" \
    -trimpath \
    -o /bouncer \
    ./cmd/bouncer/

# ---- Runtime ----
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="cs-abuseipdb-bouncer"
LABEL org.opencontainers.image.description="CrowdSec bouncer that reports malicious IPs to AbuseIPDB"
LABEL org.opencontainers.image.source="https://github.com/developingchet/cs-abuseipdb-bouncer"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.vendor="DevelopingChet"
LABEL org.opencontainers.image.sbom="https://github.com/developingchet/cs-abuseipdb-bouncer/releases/download/${VERSION}/cs-abuseipdb-bouncer.sbom.cyclonedx.json"

# CA certs for outbound HTTPS to LAPI and AbuseIPDB.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Timezone data for UTC midnight quota resets.
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

COPY --from=builder /bouncer /usr/local/bin/bouncer

# Pre-create /data owned by the nonroot user so Docker seeds the named volume
# with UID 65532 on first creation — no manual chown required.
COPY --from=builder --chown=65532:65532 /data /data

# Persistent state directory — mount a named volume here.
VOLUME ["/data"]

# Metrics, /healthz and /readyz HTTP endpoint. The binary defaults to
# 127.0.0.1:9090; inside the container it listens on all interfaces so a
# published port (or another container) can reach it. Publish it only to
# 127.0.0.1 or a private network: the endpoints are unauthenticated.
ENV METRICS_ADDR=:9090
EXPOSE 9090

# Distroless nonroot image runs as UID 65532 by default.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/bouncer"]

# `bouncer healthcheck` GETs the running process's /healthz on METRICS_ADDR
# (the image has no curl/wget). It never opens state.db, which the running
# bouncer holds under an exclusive bbolt lock. Requires METRICS_ENABLED=true.
HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=15s \
    --retries=3 \
    CMD ["/usr/local/bin/bouncer", "healthcheck"]
