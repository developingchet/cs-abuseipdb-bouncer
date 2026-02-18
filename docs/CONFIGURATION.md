# Configuration Reference

Complete reference for all configuration options in the CrowdSec AbuseIPDB Bouncer v2.0.

## Table of Contents

- [Environment Variables](#environment-variables)
  - [Required](#required-variables)
  - [Optional — AbuseIPDB](#optional--abuseipdb)
  - [Optional — Storage & Metrics](#optional--storage--metrics)
  - [Optional — Networking & Logging](#optional--networking--logging)
  - [Optional — Concurrency](#optional--concurrency)
- [Scenario Category Mapping](#scenario-category-mapping)
- [Advanced Configuration](#advanced-configuration)

---

## Environment Variables

All configuration is via environment variables (or an optional YAML file set by `CONFIG_FILE`). Set these in `.env` or pass them directly in the container's `environment` block.

---

### Required Variables

#### CROWDSEC_LAPI_URL

**Type:** String (URL)
**Required:** Yes
**Examples:** `http://crowdsec:8080`, `https://crowdsec.local:8443`

URL of the CrowdSec Local API. Use the Docker service name when CrowdSec is on the same Docker network; use a hostname or IP for a remote LAPI.

TLS is supported natively. For self-signed certificates, also set `TLS_SKIP_VERIFY=true`.

#### CROWDSEC_LAPI_KEY

**Type:** String
**Required:** Yes

The bouncer API key used to authenticate with the LAPI.

**Generate:**
```bash
docker exec crowdsec cscli bouncers add abuseipdb-bouncer
```

The key is shown only once — copy it immediately. This key grants read access to all CrowdSec decisions; treat it as a credential. The value is automatically redacted from log output by the built-in `RedactWriter`.

#### ABUSEIPDB_API_KEY

**Type:** String
**Required:** Yes
**Format:** 80-character hex v2 API key

The AbuseIPDB v2 API key for the `/report` and `/check` endpoints.

**Obtain:** https://www.abuseipdb.com/account/api

The value is automatically redacted from log output by the built-in `RedactWriter`.

**Subscription tiers:**

| Tier | Reports/day | Checks/day |
|------|-------------|------------|
| Free | 1000 | 1000 |
| Webmaster | 3000 | 3000 |
| Premium | 50000 | 50000 |

---

### Optional — AbuseIPDB

#### ABUSEIPDB_DAILY_LIMIT

**Type:** Integer
**Default:** `1000`
**Range:** 1–50000

Maximum reports to send per UTC calendar day. The counter resets at 00:00:00 UTC automatically.

Once the limit is reached, all subsequent decisions are dropped with a `quota` skip reason. No reports are sent until the counter resets. Set this to match your AbuseIPDB subscription tier.

#### ABUSEIPDB_PRECHECK

**Type:** Boolean
**Default:** `false`
**Options:** `true`, `false`, `1`, `0`, `yes`, `no`

When `true`, each IP is queried via `/check` before calling `/report`. If AbuseIPDB marks the IP as `isWhitelisted: true`, the report is skipped.

**Trade-offs:**
- Prevents wasting report quota on whitelisted IPs (CDNs, search engines, trusted infrastructure)
- Each precheck consumes one `/check` API call from the same daily quota
- Adds approximately 100–300 ms latency per decision (one additional round trip)

Recommended for Webmaster and Premium tiers where check quota is less constrained.

#### ABUSEIPDB_MIN_DURATION

**Type:** Duration string (`"5m"`, `"1h"`) or plain integer (seconds, e.g. `300`)
**Default:** `0` (disabled)

Skip decisions shorter than this duration. The decision's `duration` field is parsed and compared before enqueueing.

| Value | Effect |
|-------|--------|
| `0` | Disabled — report all decisions regardless of duration |
| `300` or `5m` | Skip bans shorter than 5 minutes (typical test decisions) |
| `3600` or `1h` | Report only bans of 1 hour or longer |
| `86400` or `24h` | Report only bans of 24 hours or longer |

---

### Optional — Storage & Metrics

#### DATA_DIR

**Type:** String (path)
**Default:** `/data`

Directory where `state.db` (the bbolt embedded database) is stored. The directory must be writable by the container user (UID 65532).

**Always mount a named Docker volume here:**

```yaml
volumes:
  - bouncer-state:/data
```

Using ephemeral container storage means the daily quota counter and per-IP cooldowns reset on every restart. A mid-day restart would start a fresh quota count, which can lead to over-reporting if the previous count was close to the limit.

The bouncer also accepts the legacy `STATE_DIR` environment variable if `DATA_DIR` is not set, for backwards-compatibility with v1.x deployments.

#### METRICS_ADDR

**Type:** String (host:port)
**Default:** `:9090`

Address on which the built-in HTTP server listens for Prometheus metrics and Kubernetes health probes.

| Endpoint | Description |
|----------|-------------|
| `GET /metrics` | Prometheus metrics in text exposition format |
| `GET /healthz` | Liveness probe — `ok` (HTTP 200) when the process is running |
| `GET /readyz` | Readiness probe — HTTP 200 when connected to LAPI, 503 otherwise |

Set to an empty string (`METRICS_ADDR=`) to disable the HTTP server entirely (no port is opened).

**Security note:** Bind to `127.0.0.1:9090` or a private network interface if the metrics endpoint should not be reachable from outside the host.

#### CONFIG_FILE

**Type:** String (path)
**Default:** _(none)_

Optional path to a YAML configuration file. Values in the file are overridden by environment variables. Useful for managing configuration in version control without duplicating all env vars.

**Example `config.yaml`:**
```yaml
abuseipdb_daily_limit: 3000
cooldown_duration: 15m
worker_count: 8
log_level: info
```

---

### Optional — Networking & Logging

#### COOLDOWN_DURATION

**Type:** Duration string
**Default:** `15m`
**Minimum:** `1m`
**Examples:** `15m`, `30m`, `1h`

Per-IP suppression window. After a report is sent for an IP, subsequent decisions for that IP are silently dropped until this window expires.

The default matches AbuseIPDB's server-side deduplication window (15 minutes). Reports within that window return HTTP 422 and consume quota without effect. Cooldown state is stored atomically in bbolt (`CooldownConsume` is a single serialised transaction) — concurrent workers cannot double-report the same IP.

Expired entries are pruned from `state.db` by the background janitor (see `JANITOR_INTERVAL`).

#### POLL_INTERVAL

**Type:** Duration string
**Default:** `30s`
**Minimum:** `10s`

How often the bouncer polls the LAPI for new decisions. Values below 10 s are rejected at startup. 30 s is appropriate for most deployments.

#### LOG_LEVEL

**Type:** String
**Default:** `info`
**Options:** `trace`, `debug`, `info`, `warn`, `error`

Controls log verbosity.

| Level | Logged events |
|-------|--------------|
| `error` | Fatal errors only |
| `warn` | Errors + warnings (rate limits, retries) |
| `info` | Warnings + startup banner, successful reports |
| `debug` | Info + every decision received and filtered |
| `trace` | Debug + internal state (not recommended in production) |

#### LOG_FORMAT

**Type:** String
**Default:** `json`
**Options:** `json`, `text`

Output format for log messages.

`json` produces structured key-value output compatible with Loki, Splunk, Elasticsearch, and similar tools:
```json
{"time":1739836530,"level":"info","ip":"203.0.113.42","sink":"abuseipdb","daily":15,"limit":1000,"msg":"reported"}
```

`text` produces human-readable output suitable for direct inspection:
```
12:15:30 INF reported ip=203.0.113.42 sink=abuseipdb daily=15 limit=1000
```

In both formats, API keys and Bearer tokens are automatically redacted from all log lines by the built-in `RedactWriter`.

#### TLS_SKIP_VERIFY

**Type:** Boolean
**Default:** `false`

When `true`, the bouncer skips TLS certificate verification when connecting to the LAPI. Required only when the LAPI uses a self-signed certificate not present in the container's CA bundle.

Do not enable this in production unless your LAPI is on a trusted private network. Enabling it removes protection against man-in-the-middle attacks on the LAPI connection.

---

### Optional — Concurrency

These settings control the worker pool introduced in v2.0. All have sensible defaults and require no changes for existing deployments.

#### WORKER_COUNT

**Type:** Integer
**Default:** `4`
**Range:** 1–64

Number of goroutines that concurrently send reports to AbuseIPDB. Each worker handles one HTTP round-trip (up to ~15 s with retries) independently, so multiple ban decisions are dispatched in parallel rather than sequentially.

Increasing this value helps during high-frequency ban waves (e.g. a DDoS generating hundreds of decisions per minute). For most deployments, the default of 4 is sufficient — AbuseIPDB API latency, not throughput, is the limiting factor.

#### WORKER_BUFFER

**Type:** Integer
**Default:** `256`
**Range:** 1–10000

Size of the in-memory job queue between the event loop and the worker pool. If new decisions arrive faster than workers can dispatch them, the queue absorbs the burst. When the queue is full, excess decisions are dropped immediately and counted in the `cs_abuseipdb_decisions_skipped_total{filter="buffer-full"}` metric.

Increase this value if you observe frequent `buffer-full` drops during burst traffic and cannot increase `WORKER_COUNT` further (e.g. due to AbuseIPDB rate limits).

#### JANITOR_INTERVAL

**Type:** Duration string
**Default:** `5m`
**Minimum:** `30s`

How often the background janitor goroutine runs. On each tick the janitor:

1. Calls `CooldownPrune()` to delete expired cooldown entries from `state.db`, bounding database growth
2. Updates the `cs_abuseipdb_bbolt_db_size_bytes` Prometheus gauge with the current file size

Values below 30 s are rejected at startup. The default of 5 minutes is appropriate for all deployments.

---

## Scenario Category Mapping

CrowdSec scenario names are mapped to AbuseIPDB category IDs using ordered substring matching. Before matching, the scenario name is lowercased and the author prefix (everything up to and including the last `/`) is stripped.

**Matching logic:**
1. Lowercase the full scenario name
2. Strip the author prefix: `crowdsecurity/ssh-bf` → `ssh-bf`
3. Test each pattern in priority order
4. The first match wins
5. If no pattern matches, category 15 (Hacking) is used as the fallback

### Complete Mapping Table

| Priority | Pattern(s) | Categories | Names |
|----------|-----------|------------|-------|
| 1 | `ssh` | 22, 18 | SSH, Brute-Force |
| 2 | `ftp` | 5, 18 | FTP Brute-Force, Brute-Force |
| 3 | `sqli`, `sql-inj`, `sql_inj` | 16, 21 | SQL Injection, Web App Attack |
| 4 | `xss` | 21 | Web App Attack |
| 5 | `wordpress`, `wp-login`, `wp_login`, `drupal`, `joomla`, `magento`, `prestashop` | 18, 21 | Brute-Force, Web App Attack |
| 6 | `ping`, `icmp` | 6 | Ping of Death |
| 7 | `http-dos`, `http-flood`, `ddos`, `flood`, `-dos` | 4 | DDoS Attack |
| 8 | `open-proxy`, `open_proxy`, `proxy`, `tor` | 9 | Open Proxy |
| 9 | `crawl`, `bad-user-agent`, `bad_user_agent`, `robot`, `scraper`, `spider`, `w00tw00t` | 19 | Bad Web Bot |
| 10 | `nmap`, `masscan`, `zmap`, `iptables` | 14 | Port Scan |
| 11 | `appsec`, `vpatch` | 21 | Web App Attack |
| 12 | `backdoor`, `rce`, `exploit`, `lfi`, `rfi`, `traversal`, `path-trav`, `log4`, `spring4`, `sensitive` | 21, 20 | Web App Attack, Exploited Host |
| 13 | `cve` | 21, 20 | Web App Attack, Exploited Host |
| 14 | `probing`, `scan`, `enum` | 14, 21 | Port Scan, Web App Attack |
| 15 | `iot`, `mirai`, `telnet` | 23, 20 | IoT Targeted, Exploited Host |
| 16 | `smtp`, `email-spam`, `email_spam`, `imap`, `pop3` | 11, 18 | Email Spam, Brute-Force |
| 17 | `http-spam`, `web-spam`, `comment-spam`, `blog-spam`, `comment_spam` | 10, 12 | Web Spam, Blog Spam |
| 18 | `phish` | 7 | Phishing |
| 19 | `spoof` | 17 | Spoofing |
| 20 | `vpn` | 13 | VPN IP |
| 21 | `dns` | 1 | DNS Compromise |
| 22 | `voip` | 8 | Fraud VoIP |
| 23 | `fraud`, `card` | 3 | Fraud Orders |
| 24 | `authelia` | 18 | Brute-Force |
| 25 | `port` | 14 | Port Scan |
| 26 | `http`, `web`, `nginx`, `apache`, `iis` | 21 | Web App Attack |
| 27 | `brute`, `-bf`, `_bf`, `rdp`, `sip`, `vnc` | 18 | Brute-Force |
| 28 | (fallback) | 15 | Hacking |

**Ordering rationale for non-obvious priorities:**
- `ping`/`icmp` (6) precedes `flood`/`ddos` (7) so that `ping-flood` matches Ping of Death rather than DDoS Attack.
- Specific scanner tools `nmap`/`masscan`/`zmap`/`iptables` (10) precede generic `scan` (14) so that `iptables-scan-multi_ports` maps only to Port Scan.
- `traversal`/`rce`/`exploit` (12) precede `probing`/`scan` (14) so that `path-traversal-probing` matches Exploited Host rather than Port Scan.
- `http-spam`/`web-spam` (17) precede `http`/`web` (26) so that `http-spam` matches Web Spam rather than Web App Attack.
- `http`/`nginx`/`apache` (26) precede `brute`/`-bf` (27) so that `nginx-bf` matches Web App Attack rather than Brute-Force.

Note: Pattern matching uses substring search (`strings.Contains`), not anchored matching. A scenario containing `ssh` anywhere will match priority 1 before priority 27 (`brute`, `-bf`).

### AbuseIPDB Category Reference

| ID | Name | Description |
|----|------|-------------|
| 1 | DNS Compromise | Altering DNS records resulting in improper redirection |
| 2 | DNS Poisoning | Forcing DNS to return incorrect IP addresses |
| 3 | Fraud Orders | Fraudulent orders |
| 4 | DDoS Attack | Participating in distributed denial-of-service |
| 5 | FTP Brute-Force | FTP login attempts |
| 6 | Ping of Death | Oversized ICMP packets |
| 7 | Phishing | Phishing websites and/or email |
| 8 | Fraud VoIP | VoIP fraud |
| 9 | Open Proxy | Open proxy, open relay, or Tor exit node |
| 10 | Web Spam | Comment/forum spam, HTTP referer spam |
| 11 | Email Spam | Spam email content, infected attachments |
| 12 | Blog Spam | CMS blog spam |
| 13 | VPN IP | IP from VPN provider |
| 14 | Port Scan | Scanning for open ports and vulnerable services |
| 15 | Hacking | Generic hacking attempts |
| 16 | SQL Injection | Attempts at SQL injection |
| 17 | Spoofing | Email sender spoofing |
| 18 | Brute-Force | Credential brute-force attacks |
| 19 | Bad Web Bot | Malicious web bots, scrapers |
| 20 | Exploited Host | Host is likely infected or compromised |
| 21 | Web App Attack | Attempt to exploit a vulnerability in a web application |
| 22 | SSH | Secure Shell (SSH) abuse |
| 23 | IoT Targeted | Targeting Internet of Things devices |

Source: https://www.abuseipdb.com/categories

Category 2 (DNS Poisoning) is defined but not emitted by any current pattern. The `*dns*` pattern maps to category 1 (DNS Compromise) only.

---

## Advanced Configuration

### Applying the Seccomp Profile

The repository ships `security/seccomp-bouncer.json`, a minimal OCI seccomp allowlist that blocks all syscalls not required by the bouncer binary.

> **Important:** The seccomp profile is read from the **host filesystem** at `docker compose up` / `docker run` time. It is not embedded in the Docker image. If the file does not exist at the path specified, Docker will refuse to start the container with an error like `no such file or directory`.

**If you cloned the repository** the file is already present under `security/` and the default compose file path (`./security/seccomp-bouncer.json`) works without any extra steps.

**If you pulled the image directly** (`docker pull`) without a local clone, download the file first:

```bash
mkdir -p security
curl -fsSL \
  https://raw.githubusercontent.com/developingchet/cs-abuseipdb-bouncer/main/security/seccomp-bouncer.json \
  -o security/seccomp-bouncer.json
```

Then run compose or `docker run` from the same directory.

**If you prefer not to use the seccomp profile**, remove that line from `security_opt` — the container is still hardened by `cap_drop: ALL`, `read_only: true`, `no-new-privileges`, and the distroless nonroot base image:

```yaml
security_opt:
  - no-new-privileges:true
  # seccomp line omitted — acceptable without a local copy of the profile
```

**docker-compose.yml (with profile):**
```yaml
security_opt:
  - no-new-privileges:true
  - "seccomp:./security/seccomp-bouncer.json"
```

**docker run (with profile):**
```bash
docker run \
  --security-opt no-new-privileges \
  --security-opt "seccomp=$(pwd)/security/seccomp-bouncer.json" \
  --env-file .env \
  --volume bouncer-state:/data \
  --read-only \
  --cap-drop ALL \
  developingchet/cs-abuseipdb-bouncer:latest
```

The seccomp profile is enforced on all modern Linux kernels (4.8+). On Docker Desktop for macOS and Windows the profile is not applied (the host kernel does not support Linux seccomp), but Docker will still fail to start the container if the file path does not exist — download the file or remove the line.

### Docker Network Isolation

To restrict the bouncer's network access to only the LAPI and AbuseIPDB:

```yaml
services:
  abuseipdb-bouncer:
    networks:
      - crowdsec-lapi
      - egress

networks:
  crowdsec-lapi:
    external: true
  egress:
    driver: bridge
```

Configure firewall rules on the host to allow outbound HTTPS from the `egress` network only to `api.abuseipdb.com` and your LAPI hostname.

### Log Aggregation

The JSON log format is suitable for parsing with standard tools.

**Loki / promtail:**

```yaml
scrape_configs:
  - job_name: abuseipdb-bouncer
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
    relabel_configs:
      - source_labels: [__meta_docker_container_name]
        regex: abuseipdb-bouncer
        action: keep
    pipeline_stages:
      - json:
          expressions:
            level: level
            msg: msg
      - labels:
          level:
```

**Splunk:**

```
[monitor:///var/lib/docker/containers/*abuseipdb-bouncer*.log]
disabled = false
index = security
sourcetype = _json
```

### Running Tests

```bash
# All unit tests with race detector (recommended before any pull request)
go test -race ./... -count=1 -timeout=120s

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

Tests run without Docker or a live LAPI — all external dependencies are mocked with `httptest.NewServer`.
