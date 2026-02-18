# ---- Builder ----
FROM golang:1.24-alpine AS builder

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
FROM gcr.io/distroless/static-debian12:nonroot

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

# Metrics, /healthz and /readyz HTTP endpoint.
EXPOSE 9090

# Distroless nonroot image runs as UID 65532 by default.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/bouncer"]

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=15s \
    --retries=3 \
    CMD ["/usr/local/bin/bouncer", "healthcheck"]
