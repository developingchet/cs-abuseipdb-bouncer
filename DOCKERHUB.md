# cs-abuseipdb-bouncer

A production-ready, security-hardened CrowdSec bouncer that reports malicious IPs to AbuseIPDB in real-time. Single static Go binary, distroless container, Prometheus metrics.

---

## Features

| Feature | Detail |
|---------|--------|
| **ACID State** | Per-IP cooldown and daily quota are stored in a [bbolt](https://github.com/etcd-io/bbolt) embedded database (`state.db`). All reads and writes run inside serialised transactions — the state is crash-consistent and survives container restarts. |
| **Prometheus Metrics** | Five metrics are exported on `GET /metrics` (port 9090 by default): decisions processed, reports sent, decisions skipped (by filter), API errors (by type), and daily quota remaining. Ready for Grafana / Alertmanager. |
| **Distroless Security** | The runtime image is `gcr.io/distroless/static-debian12:nonroot`. No shell, no package manager, no libc. Runs as UID 65532 with zero Linux capabilities and a read-only filesystem. |
| **Multi-Architecture** | Pre-built images for `linux/amd64` and `linux/arm64` on Docker Hub. Static Go binary — no libc, no CGO. |
| **Zero-Touch Releases** | Every version tag triggers a GitHub Actions pipeline: multi-arch Docker build → Trivy CVE scan (blocks on HIGH/CRITICAL) → Docker Hub push → GitHub Release with Linux/Windows binaries and SHA-256 checksums. |

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
| `METRICS_ADDR` | `:9090` | Address for `/metrics`, `/healthz`, `/readyz`. Set to empty string to disable. |
| `CONFIG_FILE` | _(none)_ | Optional path to a YAML config file (alternative / supplement to env vars). |
| `ABUSEIPDB_DAILY_LIMIT` | `1000` | Daily report quota (free=1000, webmaster=3000, premium=50000). |
| `ABUSEIPDB_PRECHECK` | `false` | Pre-check each IP with `/check` before reporting (skips whitelisted IPs). Uses one extra API call per decision. |
| `ABUSEIPDB_MIN_DURATION` | `0` | Skip decisions shorter than N seconds (e.g. `300` ignores 5-minute test bans). |
| `COOLDOWN_DURATION` | `15m` | Per-IP cooldown matching AbuseIPDB's deduplication window. |
| `POLL_INTERVAL` | `30s` | LAPI decision stream polling frequency. |
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, or `error`. |
| `LOG_FORMAT` | `json` | `json` (structured, for SIEM) or `text` (human-readable). |
| `TLS_SKIP_VERIFY` | `false` | Skip TLS verification — only for self-signed LAPI certificates. |

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

Scrape example:
```bash
curl http://localhost:9090/metrics | grep cs_abuseipdb
```

---

## Security Best Practices

### Distroless Runtime

The container image is built `FROM gcr.io/distroless/static-debian12:nonroot`. This means:

- **No shell** — eliminates RCE via shell injection; exploits that rely on `/bin/sh` are dead-ends
- **No package manager** — no `apt`, `apk`, or `pip` to install tools post-compromise
- **Minimal CVE surface** — only the Go binary and CA certificates; no libc, no OS utilities

### Read-Only Filesystem

`read_only: true` in your compose file locks down the container filesystem. The bouncer only writes to two locations:

- `/data` — the named Docker volume (bbolt `state.db`)
- `/tmp` — tmpfs mount required by the Go runtime

Everything else is immutable at runtime.

### Zero Capabilities

`cap_drop: ALL` removes every Linux capability. The bouncer needs none — it makes outbound HTTPS connections and reads from environment variables. No raw sockets, no filesystem mounting, no process manipulation.

### Non-Root User

The image runs as UID **65532** (`nonroot` in distroless convention). Even if a vulnerability were exploited, there is no path to privilege escalation — the user has no sudo access, no shell, and no capabilities.

### State Volume Placement

Always mount `DATA_DIR` as a named Docker volume:

```yaml
volumes:
  - bouncer-state:/data
```

Never use `DATA_DIR=/tmp` or store `state.db` on ephemeral container storage. The database holds your daily quota count and per-IP cooldown records — losing it means the bouncer starts a fresh quota count (harmless at midnight UTC, but undesirable mid-day) and re-enters cooldown tracking from scratch (allows re-reporting within the 15-minute deduplication window).

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
