# Configuration Reference

Complete reference for all configuration options in the CrowdSec AbuseIPDB Bouncer.

## Table of Contents

- [Environment Variables](#environment-variables)
- [Bouncer YAML Configuration](#bouncer-yaml-configuration)
- [Scenario Category Mapping](#scenario-category-mapping)
- [Advanced Configuration](#advanced-configuration)

## Environment Variables

All runtime behavior is controlled via environment variables set in `.env` or passed directly to the container.

### Required Variables

#### CROWDSEC_ABUSEIPDB_BOUNCER_KEY

**Type:** String  
**Required:** Yes  
**Format:** 32-character alphanumeric API key

The CrowdSec LAPI bouncer authentication key.

**Generate:**
```bash
docker exec crowdsec cscli bouncers add abuseipdb-reporter
```

**Example:**
```bash
CROWDSEC_ABUSEIPDB_BOUNCER_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

**Security:** This key grants read access to all CrowdSec decisions. Protect it as a credential.

#### ABUSEIPDB_API_KEY

**Type:** String  
**Required:** Yes  
**Format:** 80-character alphanumeric v2 API key

The AbuseIPDB v2 API key for authentication.

**Obtain:** https://www.abuseipdb.com/account/api

**Example:**
```bash
ABUSEIPDB_API_KEY=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

**Tiers:**
- Free: 1000 checks/day, 1000 reports/day
- Webmaster: 3000 checks/day, 3000 reports/day (verify domain ownership)
- Premium: 50000 checks/day, 50000 reports/day (paid)

### Optional Variables

#### ABUSEIPDB_DAILY_LIMIT

**Type:** Integer  
**Default:** 1000  
**Range:** 1–50000

Maximum number of reports to send per UTC calendar day.

**Behavior:**
- Counter resets at 00:00:00 UTC
- Once limit is reached, all subsequent decisions are dropped with a warning log
- Does not affect check quota (checks and reports are independent)

**Example:**
```bash
ABUSEIPDB_DAILY_LIMIT=3000  # Webmaster tier
```

**Recommendations:**
- Free tier: Set to 1000 or slightly below (900) to leave headroom for bursts
- Webmaster tier: Set to 3000
- Premium tier: Set to 50000 or lower based on expected decision volume

#### ABUSEIPDB_PRECHECK

**Type:** Boolean  
**Default:** false  
**Options:** true, false

Enable pre-check via the `/check` endpoint before reporting.

**Behavior:**
- When true: Each IP is queried via `/check` before calling `/report`
- If `isWhitelisted` is true, the report is skipped
- Uses the check quota (separate from report quota: both are 1000/day on free tier)

**Use Cases:**
- You have scenarios that occasionally trigger on known-good IPs (CDNs, search engines)
- You want to avoid wasting report quota on IPs already flagged with high confidence scores
- You have upgraded to Webmaster/Premium and can afford the check quota

**Trade-offs:**
- Doubles API calls (check + report)
- Adds ~100-200ms latency per decision
- Check quota is separate but still limited

**Example:**
```bash
ABUSEIPDB_PRECHECK=true
```

#### ABUSEIPDB_MIN_DURATION

**Type:** Integer (seconds)  
**Default:** 0  
**Range:** 0–2147483647

Minimum decision duration required for reporting. Decisions shorter than this are skipped.

**Behavior:**
- Parses the decision's `duration` field (Go duration format: "72h30m15s")
- If the duration in seconds is less than this value, the decision is skipped
- Set to 0 to disable the filter

**Use Cases:**
- Filter out test/simulation decisions (often 1-5 minutes)
- Focus on high-confidence, long-duration bans
- Reduce report volume by only reporting multi-hour bans

**Examples:**
```bash
ABUSEIPDB_MIN_DURATION=0     # Report all decisions (default)
ABUSEIPDB_MIN_DURATION=300   # Skip anything under 5 minutes
ABUSEIPDB_MIN_DURATION=3600  # Only report decisions 1 hour or longer
```

#### LOG_LEVEL

**Type:** String  
**Default:** info  
**Options:** info, debug

Controls log verbosity.

**info:**
- Startup banner
- Reports sent to AbuseIPDB
- Errors and warnings
- Daily quota exhaustion

**debug:**
- All of the above, plus:
- Every decision received (including action=del)
- Filtered decisions (private IP, wrong origin, scope, cooldown active)
- Pre-check results

**Example:**
```bash
LOG_LEVEL=debug
```

**Performance:** Debug logging adds minimal overhead (<5% in typical scenarios). Safe to leave enabled.

## Bouncer YAML Configuration

The file `config/crowdsec-custom-bouncer.yaml.tmpl` controls the bouncer's behavior.

### bin_path

**Type:** String  
**Required:** Yes  
**Value:** /abuseipdb-reporter.sh

Absolute path to the reporter script inside the container.

**Do not modify** unless you've customized the volume mounts.

### bin_args

**Type:** Array of strings  
**Default:** []

Arguments passed to the reporter script.

The reporter receives all configuration via environment variables, so this remains empty.

### feed_via_stdin

**Type:** Boolean  
**Required:** Yes  
**Value:** true

Enables stdin mode. The bouncer invokes the script once and feeds decisions as JSON objects (one per line) to its stdin.

**Do not change.** The reporter is designed for stdin mode only.

### total_retries

**Type:** Integer  
**Default:** -1

Number of times to restart the reporter if it exits.

**Value:** -1 (infinite retries)

If the script exits due to an error, the bouncer restarts it automatically.

### scopes

**Type:** Array of strings  
**Default:** [Ip]

Decision scopes to process.

**Options:**
- Ip: Single IP addresses (192.0.2.1)
- Range: CIDR ranges (192.0.2.0/24)
- AS: Autonomous system numbers
- Country: Two-letter country codes

**Recommendation:** Keep as [Ip]. AbuseIPDB only accepts single IP addresses, not ranges or ASNs.

### origins

**Type:** Array of strings  
**Default:** [crowdsec, cscli]

Decision origins to process.

**Available origins:**
- crowdsec: Local scenario detections
- cscli: Manual decisions via `cscli decisions add`
- CAPI: Community blocklist (crowd-sourced)
- lists: Imported blocklists

**Recommendation:** Keep as [crowdsec, cscli]. CAPI decisions are already known to the global community and should not be re-reported.

### cache_retention_duration

**Type:** Duration string  
**Default:** 15m

How long the bouncer caches decisions to prevent duplicate script invocations.

**Behavior:**
- If a decision with the same type and value arrives within this window, the script is not invoked
- This is the first deduplication layer (before the script's per-IP cooldown)

**Recommendation:** Keep at 15m to match AbuseIPDB's server-side deduplication window.

### update_frequency

**Type:** Duration string  
**Default:** 30s

How often the bouncer polls the LAPI for new decisions.

**Range:** 10s–300s

**Trade-offs:**
- Lower values: Faster reporting, more LAPI load
- Higher values: Delayed reporting, less LAPI load

**Recommendation:** 30s is a good balance. CrowdSec decisions are not time-critical for AbuseIPDB reporting.

### log_mode

**Type:** String  
**Default:** stdout  
**Options:** stdout, file

Where the bouncer writes its logs.

**stdout:** Logs go to Docker's log driver (captured by `docker logs`)  
**file:** Logs written to log_dir

**Recommendation:** Use stdout for Docker deployments.

### log_level

**Type:** String  
**Default:** info  
**Options:** trace, debug, info, error

Bouncer's internal log level (distinct from the reporter's LOG_LEVEL).

**Recommendation:** Keep at info unless debugging bouncer startup issues.

### api_url

**Type:** String (URL)  
**Required:** Yes

CrowdSec LAPI address.

**Format:** `http(s)://hostname:port`

**Examples:**
```yaml
api_url: https://crowdsec.local:8443              # TLS-enabled LAPI
api_url: http://crowdsec:8080                     # Plain HTTP (same Docker network)
api_url: https://remote-crowdsec.example.com:8443 # Remote LAPI
```

**Must match** the hostname in `docker-compose.yml` extra_hosts.

### api_key

**Type:** String  
**Value:** __CROWDSEC_ABUSEIPDB_BOUNCER_KEY__

Placeholder replaced by the entrypoint script with the value of $CROWDSEC_ABUSEIPDB_BOUNCER_KEY.

**Do not modify this line.**

### insecure_skip_verify

**Type:** Boolean  
**Default:** false (not present)

Skip TLS certificate verification.

**Use when:**
- LAPI uses a self-signed certificate
- Internal CA that's not in the container's trust store

**Example:**
```yaml
insecure_skip_verify: true
```

**Security:** Only use in trusted networks. Disables MITM protection.

## Scenario Category Mapping

CrowdSec scenario names are mapped to AbuseIPDB category IDs via substring matching in the reporter script. The scenario name is lowercased and the author prefix is stripped before matching.

**Matching Logic:**
1. Scenario string is converted to lowercase
2. Author prefix is removed (e.g., "crowdsecurity/ssh-bf" becomes "ssh-bf")
3. Patterns are tested in order
4. **First match wins**
5. If no pattern matches, category 15 (Hacking) is used

### Complete Mapping Table

| Priority | Pattern | Categories | Category Names | Examples |
|----------|---------|------------|----------------|----------|
| 1 | `*ssh*` | 22, 18 | SSH, Brute-Force | crowdsecurity/ssh-bf, ssh-slow-bf, ssh-cve-2024-* |
| 2 | `*ftp*` | 5, 18 | FTP Brute-Force, Brute-Force | crowdsecurity/ftp-bf |
| 3 | `*sqli*`, `*sql-inj*`, `*sql_inj*` | 16, 21 | SQL Injection, Web App Attack | http-sqli-probing |
| 4 | `*xss*` | 21 | Web App Attack | http-xss-probing |
| 5 | `*wordpress*`, `*wp-login*`, `*wp_login*`, `*drupal*`, `*joomla*`, `*magento*`, `*prestashop*` | 18, 21 | Brute-Force, Web App Attack | http-bf-wordpress_bf, wordpress-scan, drupal-cve-* |
| 6 | `*http-dos*`, `*http-flood*`, `*ddos*`, `*flood*`, `*-dos*` | 4 | DDoS Attack | http-dos-generic, ddos, syn-flood |
| 7 | `*open-proxy*`, `*open_proxy*`, `*proxy*`, `*tor*` | 9 | Open Proxy | http-open-proxy, tor-exit-node |
| 8 | `*crawl*`, `*bad-user-agent*`, `*bad_user_agent*`, `*robot*`, `*scraper*`, `*spider*`, `*w00tw00t*` | 19 | Bad Web Bot | http-crawl-non_statics, bad-user-agent, w00tw00t |
| 9 | `*probing*`, `*scan*`, `*enum*` | 14, 21 | Port Scan, Web App Attack | http-probing, iptables-scan-multi_ports, http-admin-interface-probing |
| 10 | `*appsec*`, `*vpatch*` | 21 | Web App Attack | appsec-native, vpatch-env-access |
| 11 | `*backdoor*`, `*rce*`, `*exploit*`, `*lfi*`, `*rfi*`, `*traversal*`, `*path-trav*`, `*log4*`, `*spring4*`, `*sensitive*` | 21, 20 | Web App Attack, Exploited Host | http-backdoors-attempts, path-traversal-probing, apache_log4j2_cve-2021-44228 |
| 12 | `*cve*` | 21, 20 | Web App Attack, Exploited Host | grafana-cve-2021-43798, ssh-cve-2024-6387 |
| 13 | `*iot*`, `*mirai*`, `*telnet*` | 23, 20 | IoT Targeted, Exploited Host | mirai-generic, telnet-bf |
| 14 | `*smtp*`, `*email-spam*`, `*email_spam*`, `*imap*`, `*pop3*` | 11, 18 | Email Spam, Brute-Force | smtp-spam, imap-bf |
| 15 | `*http-spam*`, `*web-spam*`, `*comment-spam*`, `*blog-spam*`, `*comment_spam*` | 10, 12 | Web Spam, Blog Spam | http-spam, blog-comment-spam |
| 16 | `*phish*` | 7 | Phishing | phishing-url |
| 17 | `*spoof*` | 17 | Spoofing | ip-spoofing |
| 18 | `*vpn*` | 13 | VPN IP | vpn-detection |
| 19 | `*dns*` | 1 | DNS Compromise | dns-amplification |
| 20 | `*ping*`, `*icmp*` | 6 | Ping of Death | ping-flood, icmp-flood |
| 21 | `*voip*` | 8 | Fraud VoIP | voip-bf |
| 22 | `*fraud*`, `*card*` | 3 | Fraud Orders | credit-card-fraud |
| 23 | `*authelia*` | 18 | Brute-Force | LePresidente/authelia-bf |
| 24 | `*iptables*`, `*port*`, `*nmap*`, `*masscan*`, `*zmap*` | 14 | Port Scan | iptables-scan-multi_ports, nmap-scan |
| 25 | `*brute*`, `*-bf*`, `*_bf*`, `*rdp*`, `*sip*`, `*vnc*` | 18 | Brute-Force | generic-bf, rdp-bf, sip-bf |
| 26 | `*http*`, `*web*`, `*nginx*`, `*apache*`, `*iis*` | 21 | Web App Attack | http-generic-bf, nginx-bf |
| 27 | (fallback) | 15 | Hacking | Any scenario not matched above |

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
| 23 | IoT Targeted | Targeting Internet of Things (IoT) devices |

Source: https://www.abuseipdb.com/categories

## Advanced Configuration

### Custom Scenario Mappings

To add or modify scenario mappings, edit the `categories()` function in `scripts/crowdsec-abuseipdb-reporter.sh`.

**Example: Add a custom scenario**

If you have a custom scenario `mycompany/api-abuse` that should map to category 21 (Web App Attack):

```bash
categories() {
    local s
    s=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    s="${s##*/}"
    case "$s" in
        *ssh*)                                          printf '22,18' ;;
        # ... existing patterns ...
        *api-abuse*)                                    printf '21' ;;  # Add this line
        *)                                              printf '15' ;;
    esac
}
```

**Important:** Add specific patterns before generic ones. Patterns are tested in order and the first match wins.

### Docker Network Isolation

For maximum security, place the bouncer in a dedicated network with access only to the LAPI and internet.

**Example docker-compose.yml:**

```yaml
services:
  abuseipdb-bouncer:
    networks:
      - crowdsec-lapi
      - internet

networks:
  crowdsec-lapi:
    external: true
  internet:
    driver: bridge
```

Then configure firewall rules to allow:
- Outbound HTTPS to api.abuseipdb.com
- Outbound HTTPS to your LAPI
- Block all other traffic

### Log Aggregation

The bouncer logs are structured and suitable for parsing.

**Loki example (promtail):**

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
      - regex:
          expression: 'time="(?P<time>[^"]+)" level=(?P<level>\S+) msg="(?P<msg>[^"]+)"'
      - labels:
          level:
```

**Splunk example:**

```
[monitor:///var/lib/docker/containers/*abuseipdb-bouncer*.log]
disabled = false
index = security
sourcetype = abuseipdb_bouncer
```

### Prometheus Metrics

The bouncer binary exposes Prometheus metrics on port 60602 inside the container.

**Available metrics:**
- `cs_bouncer_decisions_total{origin,scenario,type}` - Total decisions processed
- `cs_bouncer_custom_script_exits_total` - Script exit count

**Expose in docker-compose.yml:**

```yaml
ports:
  - "60602:60602"
```

**Scrape configuration:**

```yaml
scrape_configs:
  - job_name: abuseipdb-bouncer
    static_configs:
      - targets: ['localhost:60602']
```

### Running Multiple Reporters

To run multiple instances (e.g., for redundancy or different AbuseIPDB accounts):

1. Create separate service definitions in docker-compose.yml
2. Use different container names and bouncer keys
3. Share the same state volume OR use separate volumes (separate cooldown tracking)

**Shared state example:**

```yaml
services:
  abuseipdb-bouncer-primary:
    # ... config ...
    volumes:
      - abuseipdb-state:/tmp/cs-abuseipdb
  
  abuseipdb-bouncer-backup:
    # ... config with different ABUSEIPDB_API_KEY ...
    volumes:
      - abuseipdb-state:/tmp/cs-abuseipdb  # Same volume
```

Shared state ensures the same IP isn't reported twice within the cooldown window, even across instances.
