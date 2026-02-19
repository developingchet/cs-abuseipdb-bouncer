# cs-abuseipdb-bouncer

A production-ready, security-hardened CrowdSec bouncer that reports malicious IPs to AbuseIPDB in real-time. Single static Go binary, distroless container, Prometheus metrics.

---

## Features

| Feature | Detail |
|---------|--------|
| **Concurrent Worker Pool** | A configurable pool of goroutines sends reports to AbuseIPDB in parallel. High-frequency ban waves no longer stall the main event loop. Backpressure is handled via a bounded channel; overflow is counted in the `buffer-full` filter metric. |
| **ACID State** | Per-IP cooldown and daily quota are stored in a [bbolt](https://github.com/etcd-io/bbolt) embedded database (`state.db`). Quota and cooldown checks execute as single atomic transactions — no TOCTOU races, crash-consistent, survives container restarts. |
| **Prometheus Metrics** | Six metrics are exported on `GET /metrics` (port 9090 by default): decisions processed, reports sent, decisions skipped (by filter), API errors (by type), daily quota remaining, and `state.db` file size. Ready for Grafana / Alertmanager. |
| **Distroless Security** | The runtime image is `gcr.io/distroless/static-debian12:nonroot`. No shell, no package manager, no libc. Runs as UID 65532 with zero Linux capabilities and a read-only filesystem. Seccomp syscall allowlist applied by default in the provided `docker-compose.yml`. |
| **Supply-Chain Provenance** | Every release is signed with [Cosign](https://docs.sigstore.dev/cosign/overview/) (keyless OIDC — no stored private key) and accompanied by a CycloneDX SBOM attached as a Cosign attestation and a GitHub Release asset. |
| **Multi-Architecture** | Pre-built images for `linux/amd64` and `linux/arm64` on Docker Hub. Static Go binary — no libc, no CGO. |
| **Zero-Touch Releases** | Every version tag triggers a GitHub Actions pipeline: tests (with `-race`) → Trivy CVE scan (blocks on HIGH/CRITICAL) → multi-arch Docker build → Cosign sign + SBOM → Docker Hub push → GitHub Release with binaries and SHA-256 checksums. |

---

## Quick Start

```yaml
# docker-compose.yml (minimal)
services:
  abuseipdb-bouncer:
    image: developingchet/cs-abuseipdb-bouncer:latest
    restart: unless-stopped
    environment:
      - CROWDSEC_LAPI_URL=http://crowdsec:8080
      - CROWDSEC_LAPI_KEY=${CROWDSEC_LAPI_KEY}
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
      - DATA_DIR=/data
      - METRICS_ADDR=:9090
    volumes:
      - bouncer-state:/data
    ports:
      - "127.0.0.1:9090:9090"
    tmpfs:
      - /tmp:size=10M,uid=65532,gid=65532,mode=1777
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    networks:
      - crowdsec-net

volumes:
  bouncer-state:

networks:
  crowdsec-net:
    external: true
```

Get your LAPI key: `docker exec crowdsec cscli bouncers add abuseipdb-bouncer`

---

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `CROWDSEC_LAPI_URL` | URL of the CrowdSec Local API (e.g. `http://crowdsec:8080`) |
| `CROWDSEC_LAPI_KEY` | Bouncer API key from `cscli bouncers add` |
| `ABUSEIPDB_API_KEY` | AbuseIPDB v2 API key from abuseipdb.com/account/api |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_DIR` | `/data` | Directory for `state.db` (bbolt database). Mount a named volume here. |
| `METRICS_ENABLED` | `true` | Set to `false` to disable the `/metrics`, `/healthz`, `/readyz` HTTP server entirely (no port opened). Takes precedence over `METRICS_ADDR`. |
| `METRICS_ADDR` | `:9090` | Address for `/metrics`, `/healthz`, `/readyz`. Ignored when `METRICS_ENABLED=false`. Set to empty string to disable. |
| `CONFIG_FILE` | _(none)_ | Optional path to a YAML config file (alternative / supplement to env vars). |
| `ABUSEIPDB_DAILY_LIMIT` | `1000` | Daily report quota (free=1000, webmaster=3000, premium=50000). |
| `ABUSEIPDB_PRECHECK` | `false` | Pre-check each IP with `/check` before reporting (skips whitelisted IPs). Uses one extra API call per decision. |
| `ABUSEIPDB_MIN_DURATION` | `0` | Skip decisions shorter than N seconds (e.g. `300` ignores 5-minute test bans). |
| `IP_WHITELIST` | _(none)_ | Comma-separated IPs/CIDRs to skip reporting (e.g. `203.0.113.0/24,2001:db8::/32`). |
| `COOLDOWN_DURATION` | `15m` | Per-IP cooldown matching AbuseIPDB's deduplication window. |
| `POLL_INTERVAL` | `30s` | LAPI decision stream polling frequency. |
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, or `error`. |
| `LOG_FORMAT` | `json` | `json` (structured, for SIEM) or `text` (human-readable). |
| `TLS_SKIP_VERIFY` | `false` | Skip TLS verification — only for self-signed LAPI certificates. |
| `WORKER_COUNT` | `4` | Number of goroutines that concurrently send reports to AbuseIPDB (range: 1–64). |
| `WORKER_BUFFER` | `256` | Size of the in-memory job queue between the event loop and workers (range: 1–10000). |
| `JANITOR_INTERVAL` | `5m` | How often the background janitor prunes expired cooldown entries and updates the DB size metric (minimum: 30s). |

---

## Observability

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /metrics` | Prometheus metrics in text exposition format |
| `GET /healthz` | Liveness probe — returns `ok` (HTTP 200) when the process is running |
| `GET /readyz` | Readiness probe — HTTP 200 when connected to LAPI, 503 otherwise |

### Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `cs_abuseipdb_decisions_processed_total` | Counter | — | All decisions received from the LAPI stream |
| `cs_abuseipdb_reports_sent_total` | Counter | — | Successful reports sent to AbuseIPDB |
| `cs_abuseipdb_decisions_skipped_total` | Counter | `filter` | Decisions dropped by each filter stage |
| `cs_abuseipdb_api_errors_total` | Counter | `type` | API errors by type: `rate_limit`, `auth`, `network`, `timeout` |
| `cs_abuseipdb_quota_remaining` | Gauge | — | Remaining daily report quota (resets at UTC midnight) |
| `cs_abuseipdb_bbolt_db_size_bytes` | Gauge | — | Size of `state.db` in bytes, updated by the janitor |

Scrape example:
```bash
curl http://localhost:9090/metrics | grep cs_abuseipdb
```

---

## Security

### Distroless Runtime

The container image is built `FROM gcr.io/distroless/static-debian12:nonroot`. This means:

- **No shell** — eliminates RCE via shell injection
- **No package manager** — no `apt`, `apk`, or `pip` to install tools post-compromise
- **Minimal CVE surface** — only the Go binary and CA certificates

### Seccomp Profile

The repository ships `security/seccomp-bouncer.json`, a minimal OCI seccomp profile that allows only the syscalls the binary actually needs.

> **The file must exist on your host.** It is read from the host filesystem at container start — it is not embedded in the image. Docker will refuse to start if the path does not exist.

**If you cloned the repo**, `./security/seccomp-bouncer.json` is already present. Otherwise, download it first:

```bash
mkdir -p security
curl -fsSL \
  https://raw.githubusercontent.com/developingchet/cs-abuseipdb-bouncer/main/security/seccomp-bouncer.json \
  -o security/seccomp-bouncer.json
```

Then apply it in your compose file:

```yaml
security_opt:
  - no-new-privileges:true
  - "seccomp:./security/seccomp-bouncer.json"
```

If you prefer not to download the file, simply omit that line — `cap_drop: ALL`, `read_only: true`, and the distroless nonroot image still provide strong isolation without it.

> If the container crash-loops with `operation not permitted`, the installed profile may be outdated. See [Troubleshooting](https://github.com/developingchet/cs-abuseipdb-bouncer/blob/main/docs/TROUBLESHOOTING.md#seccomp-profile-blocks-container-startup) for the fix.

### Log Redaction

API keys and Bearer tokens are automatically redacted from all log output before they reach stderr. The regex patterns match 80-character hex strings (AbuseIPDB / CrowdSec key format) and `Bearer <token>` values.

### Supply-Chain Verification

Verify the image signature with Cosign:

```bash
cosign verify developingchet/cs-abuseipdb-bouncer:latest \
  --certificate-identity-regexp="https://github.com/developingchet/cs-abuseipdb-bouncer/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

A CycloneDX SBOM is available as a GitHub Release asset and embedded as a Cosign attestation on the image.

---

## Migration from v1.x

| Aspect | v1.x | v2.0 |
|--------|------|-------|
| State env var | `STATE_DIR` | `DATA_DIR` |
| Default path | `/tmp/cs-abuseipdb` | `/data` |
| Storage format | `daily` file + `cooldown/` directory | `state.db` (bbolt embedded database) |
| Volume mount | `bouncer-state:/tmp/cs-abuseipdb` | `bouncer-state:/data` |
| New in v2.0 | — | `METRICS_ADDR`, `CONFIG_FILE` |

**No migration script is needed.** On first start, v2.0 creates a fresh `state.db`. The quota counter resets at UTC midnight anyway, and cooldowns rebuild within one 15-minute window.

Update your compose file:
1. Change `STATE_DIR=/tmp/cs-abuseipdb` → `DATA_DIR=/data`
2. Change `- bouncer-state:/tmp/cs-abuseipdb` → `- bouncer-state:/data`
3. Optionally add `METRICS_ADDR=:9090` and expose port 9090

---

## Links

- **GitHub Repository:** https://github.com/developingchet/cs-abuseipdb-bouncer
- **Setup Guide:** https://github.com/developingchet/cs-abuseipdb-bouncer/blob/main/docs/SETUP.md
- **Configuration Reference:** https://github.com/developingchet/cs-abuseipdb-bouncer/blob/main/docs/CONFIGURATION.md
- **Troubleshooting:** https://github.com/developingchet/cs-abuseipdb-bouncer/blob/main/docs/TROUBLESHOOTING.md
- **Issues / Bug Reports:** https://github.com/developingchet/cs-abuseipdb-bouncer/issues
