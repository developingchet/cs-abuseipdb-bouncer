# Configuration Reference

Complete reference for all configuration options in the CrowdSec AbuseIPDB Bouncer.

## Table of Contents

- [Environment Variables](#environment-variables)
- [Scenario Category Mapping](#scenario-category-mapping)
- [Advanced Configuration](#advanced-configuration)

## Environment Variables

All configuration is via environment variables. No configuration files are needed -- set these in `.env` or pass them directly in the container's `environment` block.

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

The key is only shown once. Copy it immediately. This key grants read access to all CrowdSec decisions -- treat it as a credential.

#### ABUSEIPDB_API_KEY

**Type:** String
**Required:** Yes
**Format:** 80-character alphanumeric v2 API key

The AbuseIPDB v2 API key for the `/report` and `/check` endpoints.

**Obtain:** https://www.abuseipdb.com/account/api

**Subscription tiers:**

| Tier | Reports/day | Checks/day |
|------|-------------|------------|
| Free | 1000 | 1000 |
| Webmaster | 3000 | 3000 |
| Premium | 50000 | 50000 |

### Optional Variables

#### ABUSEIPDB_DAILY_LIMIT

**Type:** Integer
**Default:** 1000
**Range:** 1-50000

Maximum reports to send per UTC calendar day. The counter resets at 00:00:00 UTC automatically.

Once the limit is reached, all subsequent decisions are dropped with a `warn` log and the daily count is preserved to disk. No reports are sent until the counter resets.

Set this to match your AbuseIPDB subscription tier. Setting it slightly below the hard limit (e.g., 950 instead of 1000) leaves headroom for manual API calls.

#### ABUSEIPDB_PRECHECK

**Type:** Boolean
**Default:** false
**Options:** true, false, 1, 0, yes, no

When true, each IP is queried via `/check` before calling `/report`. If AbuseIPDB marks the IP as `isWhitelisted: true`, the report is skipped.

**Trade-offs:**
- Prevents wasting report quota on whitelisted IPs (CDNs, search engines, trusted infrastructure)
- Each precheck consumes one `/check` API call from the same daily quota
- Adds approximately 100-300ms latency per decision (one additional round trip)

Recommended for Webmaster and Premium tiers where check quota is less constrained.

#### ABUSEIPDB_MIN_DURATION

**Type:** Integer (seconds)
**Default:** 0

Skip decisions shorter than this many seconds. The decision's `duration` field (Go duration format: "72h30m15s") is parsed and compared.

Set to 0 to disable and report all decisions regardless of duration.

| Value | Effect |
|-------|--------|
| 0 | Disabled -- report all decisions |
| 300 | Skip bans shorter than 5 minutes (typical test decisions) |
| 3600 | Report only bans of 1 hour or longer |
| 86400 | Report only bans of 24 hours or longer |

#### COOLDOWN_DURATION

**Type:** Duration string
**Default:** 15m
**Minimum:** 1m
**Examples:** `15m`, `30m`, `1h`

Per-IP suppression window. After a report is sent for an IP, subsequent decisions for that IP are dropped until this window expires.

The default matches AbuseIPDB's server-side deduplication window (15 minutes). Reports within that window return HTTP 422 and consume quota without effect.

Increasing this value reduces duplicate reports but also delays legitimate re-reporting when an IP resumes attacks after a quiet period.

#### POLL_INTERVAL

**Type:** Duration string
**Default:** 30s
**Minimum:** 10s

How often the bouncer polls the LAPI for new decisions.

Lower values reduce the time between detection and reporting, at the cost of higher LAPI load. Values below 10s are rejected at startup. 30s is appropriate for most deployments.

#### LOG_LEVEL

**Type:** String
**Default:** info
**Options:** trace, debug, info, warn, error

Controls log verbosity.

| Level | Logged events |
|-------|--------------|
| error | Fatal errors only |
| warn | Errors + warnings (rate limits, retries) |
| info | Warnings + startup banner, successful reports |
| debug | Info + every decision received and filtered |
| trace | Debug + internal state (not recommended in production) |

Debug mode logs every decision including filtered ones, which is useful when investigating why certain IPs are not being reported.

#### LOG_FORMAT

**Type:** String
**Default:** json
**Options:** json, text

Output format for log messages.

`json` produces structured key-value output compatible with Loki, Splunk, Elasticsearch, and similar tools:
```json
{"time":1739836530,"level":"info","ip":"203.0.113.42","daily":15,"limit":1000,"msg":"reported"}
```

`text` produces human-readable output suitable for direct inspection:
```
12:15:30 INF reported ip=203.0.113.42 daily=15 limit=1000
```

#### TLS_SKIP_VERIFY

**Type:** Boolean
**Default:** false

When true, the bouncer skips TLS certificate verification when connecting to the LAPI. This is required when the LAPI uses a self-signed certificate that is not in the container's CA bundle.

Do not enable this in production unless your LAPI is on a trusted network and certificate verification is not feasible. Enabling it removes protection against man-in-the-middle attacks on the LAPI connection.

#### STATE_DIR

**Type:** String
**Default:** /tmp/cs-abuseipdb

Directory where per-IP cooldown files and the daily quota counter are stored. The directory must be writable by the container user (UID 65532).

In production, mount a named Docker volume at this path so state persists across container restarts. Using an in-memory tmpfs means the daily counter and cooldowns reset on every restart, which can lead to quota overruns.

---

## Scenario Category Mapping

CrowdSec scenario names are mapped to AbuseIPDB category IDs using ordered substring matching. Before matching, the scenario name is lowercased and the author prefix (everything up to and including the last `/`) is stripped.

**Matching logic:**
1. Lowercase the full scenario name
2. Strip the author prefix: `crowdsecurity/ssh-bf` becomes `ssh-bf`
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
- Specific scanner tools `nmap`/`masscan`/`zmap`/`iptables` (10) precede generic `scan` (14) so that `iptables-scan-multi_ports` maps only to Port Scan rather than Port Scan + Web App Attack.
- `traversal`/`rce`/`exploit` (12) precede `probing`/`scan` (14) so that `path-traversal-probing` matches Exploited Host rather than Port Scan.
- `http-spam`/`web-spam` (17) precede `http`/`web` (26) so that `http-spam` matches Web Spam rather than Web App Attack.
- `http`/`nginx`/`apache` (26) precede `brute`/`-bf` (27) so that `nginx-bf` matches Web App Attack rather than Brute-Force.

Note: Pattern matching uses substring search (`strings.Contains`), not anchored matching. A scenario containing `ssh` anywhere will match priority 1 before priority 27 (`brute`, `-bf`). This is why SSH scenarios correctly receive categories 22 and 18 rather than just 18.

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
# All unit tests
go test ./...

# With race detector (recommended before pull requests)
go test -race ./...

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

Tests run without Docker or a live LAPI -- all external dependencies are mocked with `httptest.NewServer`.
