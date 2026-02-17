# External References

Comprehensive list of external documentation, research sources, and relevant links used in the development of the CrowdSec AbuseIPDB Bouncer.

## Table of Contents

- [Official Documentation](#official-documentation)
- [API Specifications](#api-specifications)
- [Research and Best Practices](#research-and-best-practices)
- [Community Resources](#community-resources)
- [Related Projects](#related-projects)

## Official Documentation

### CrowdSec

**Main Documentation**
- CrowdSec Documentation Hub: https://docs.crowdsec.net/
- Introduction to CrowdSec: https://docs.crowdsec.net/docs/intro

**Local API (LAPI)**
- LAPI Introduction: https://docs.crowdsec.net/docs/next/local_api/intro
- LAPI Authentication: https://docs.crowdsec.net/docs/next/local_api/authentication
- Decisions Management API: https://docs.crowdsec.net/docs/next/local_api/decisions_mgmt
- Decisions Streaming: https://docs.crowdsec.net/docs/next/local_api/decisions_streaming

**Custom Bouncer Framework**
- Custom Bouncer Documentation: https://docs.crowdsec.net/u/bouncers/custom/
- Configuration Reference: https://docs.crowdsec.net/u/bouncers/custom/#configuration-reference
- Stdin Mode: https://docs.crowdsec.net/u/bouncers/custom/#stdin-mode
- Docker Image: https://hub.docker.com/r/crowdsecurity/custom-bouncer
- GitHub Repository: https://github.com/crowdsecurity/cs-custom-bouncer

**CLI (cscli)**
- cscli Reference: https://docs.crowdsec.net/docs/next/cscli/cscli
- Bouncer Management: https://docs.crowdsec.net/docs/next/cscli/cscli_bouncers_add
- Decision Management: https://docs.crowdsec.net/docs/next/cscli/cscli_decisions

**Scenarios and Parsers**
- Scenarios Concepts: https://docs.crowdsec.net/docs/next/scenarios/intro
- Hub Browser: https://hub.crowdsec.net/
- Scenario Format: https://docs.crowdsec.net/docs/next/scenarios/format

### AbuseIPDB

**API Documentation**
- API v2 Documentation: https://docs.abuseipdb.com/
- Report Endpoint: https://docs.abuseipdb.com/#report-endpoint
- Check Endpoint: https://docs.abuseipdb.com/#check-endpoint
- Blacklist Download: https://docs.abuseipdb.com/#blacklist-endpoint

**Categories**
- Category List/Definitions: https://www.abuseipdb.com/categories

**Account and Billing**
- API Key Management: https://www.abuseipdb.com/account/api
- Webmaster Tier (free upgrade): https://www.abuseipdb.com/account/webmasters
- Premium Pricing: https://www.abuseipdb.com/pricing

**Policies and Guidelines**
- FAQ: https://www.abuseipdb.com/faq
- Terms of Service: https://www.abuseipdb.com/legal/terms
- Privacy Policy: https://www.abuseipdb.com/legal/privacy
- Reporting Guidelines: https://www.abuseipdb.com/faq#reporting

## API Specifications

### AbuseIPDB v2 API Details

**Report Endpoint Specification**

```
POST https://api.abuseipdb.com/api/v2/report
Headers:
  Key: <api_key>
  Accept: application/json
Parameters:
  ip: <single IP address>
  categories: <comma-separated category IDs>
  comment: <optional comment, max 1024 chars>
```

**Response Codes:**
- 200: Success
- 400: Bad request (invalid IP, missing parameters)
- 401: Unauthorized (invalid API key)
- 422: Unprocessable Entity (duplicate within 15 minutes, or IP is whitelisted)
- 429: Too Many Requests (rate limit exceeded)

**Rate Limits (as of 2026):**
- Free tier: 1000 reports/day, 1000 checks/day
- Webmaster tier: 3000 reports/day, 3000 checks/day
- Premium tier: 50000 reports/day, 50000 checks/day
- Per-IP deduplication: 15 minutes (server-enforced)

**Check Endpoint Specification**

```
GET https://api.abuseipdb.com/api/v2/check
Headers:
  Key: <api_key>
  Accept: application/json
Parameters:
  ipAddress: <IP address>
  maxAgeInDays: <1-365>
  verbose: <optional, detailed response>
```

**Response Fields:**
- `abuseConfidenceScore`: 0-100 confidence percentage
- `totalReports`: Total reports in time window
- `isWhitelisted`: Boolean (true for known-good IPs)
- `isTor`: Boolean (true for Tor exit nodes)
- `usageType`: ISP, Commercial, Military, etc.

### CrowdSec LAPI Decision Object Format

**Decision Stream Response:**

```json
{
  "new": [
    {
      "id": 1234567,
      "duration": "143h58m15s",
      "origin": "crowdsec",
      "scenario": "crowdsecurity/ssh-bf",
      "scope": "Ip",
      "type": "ban",
      "value": "203.0.113.42",
      "simulated": false
    }
  ],
  "deleted": [...]
}
```

**Field Definitions:**
- `id`: Unique decision identifier
- `duration`: Go duration format (e.g., "72h30m15s")
- `origin`: "crowdsec" (local), "cscli" (manual), "CAPI" (community), "lists" (imported)
- `scenario`: Full scenario name with author (e.g., "crowdsecurity/ssh-bf")
- `scope`: "Ip", "Range", "Country", "AS"
- `type`: "ban" (typical), "captcha", "throttle"
- `value`: IP address, CIDR, country code, or ASN
- `simulated`: Boolean (true if running in simulation mode)

## Research and Best Practices

### AbuseIPDB Best Practices Research

**Findings from FAQ and Community:**

1. **Check and Report Quotas are Independent**
   - Source: https://www.abuseipdb.com/faq#api-limits
   - Check quota: 1000/day
   - Report quota: 1000/day
   - They do not share a combined pool

2. **Whitelisted IPs Should Not Be Reported**
   - Source: https://www.abuseipdb.com/faq#whitelist
   - CDNs, major cloud providers, search engines are often whitelisted
   - Reporting them wastes quota (returns 422)
   - Use `/check` endpoint with `isWhitelisted` field to pre-filter

3. **15-Minute Deduplication Window**
   - Source: https://docs.abuseipdb.com/#report-endpoint
   - Server rejects duplicate reports for the same IP within 15 minutes
   - Returns HTTP 422 with error message
   - Client-side cooldown should match this window

4. **Comment Field Guidelines**
   - Source: https://www.abuseipdb.com/faq#comments
   - Max 1024 characters
   - Should be concise and machine-parseable
   - Avoid dumping entire log files
   - No PII (email addresses, usernames, etc.)
   - Example: "SSH brute force | 200 failed attempts"

5. **TLS 1.2 Requirement**
   - Source: API deprecation notice (2023)
   - TLS 1.0 and 1.1 deprecated
   - SSLv2/SSLv3 disabled
   - Clients must support TLS 1.2 or higher

### CrowdSec Decision Origins Research

**Decision Origin Behavior:**

- **crowdsec**: Generated by local parsers and scenarios
  - These are detections from your own logs
  - Suitable for reporting to AbuseIPDB

- **cscli**: Manual decisions added via CLI
  - Example: `cscli decisions add -i 1.2.3.4 -d 24h -r "manual ban"`
  - Suitable for reporting (administrator judgment)

- **CAPI (Community)**: Shared via CrowdSec's Central API
  - IPs reported by other CrowdSec users
  - Already in the global database
  - Should NOT be re-reported to AbuseIPDB (redundant)

- **lists**: Imported blocklists (FireHOL, Spamhaus, etc.)
  - Third-party threat feeds
  - Should NOT be reported (not your detection)

**Source:** CrowdSec documentation on decision origins (https://docs.crowdsec.net/docs/next/local_api/decisions_mgmt)

### Shell Scripting Research

**POSIX ash vs bash Differences:**

Research conducted on Alpine Linux BusyBox ash compatibility:

1. **No process substitution**: `<(command)` not supported
   - Workaround: Use temp files with mktemp

2. **No `[[` operator**: Only `[` is available
   - Workaround: Use `[` with proper quoting

3. **No arrays**: Only space-separated strings
   - Workaround: Use `for var in $list` with careful IFS handling

4. **`local` exit code masking**: `local var=$(cmd)` masks cmd exit code under `set -e`
   - Workaround: Declare and assign separately
   - Example:
     ```bash
     local result
     result=$(command)  # Command failure will trigger set -e
     ```

5. **Limited `printf` format support**: No `%q` for shell quoting
   - Workaround: Use manual escaping or avoid need for quoting

**Source:** BusyBox documentation (https://busybox.net/downloads/BusyBox.html)

### Docker Logging with Child Processes

**Problem Discovery:** Child process stdout/stderr not captured by `docker logs` when parent uses `exec.Cmd` with default settings.

**Root Cause:** Go's `exec.Cmd` defaults `Stdout` and `Stderr` to `nil`, which discards output.

**Solution:** Write to `/proc/1/fd/2` (container PID 1's stderr) directly from child script, bypassing parent process file descriptor inheritance.

**Verification:**
```bash
# This works
docker exec container cat /proc/1/fd/2

# This doesn't work if parent fd is nil
docker logs container
```

**Source:** Docker documentation on logging drivers (https://docs.docker.com/config/containers/logging/)

## Community Resources

### CrowdSec Community

- **Discord**: https://discord.gg/crowdsec
- **Discourse Forum**: https://discourse.crowdsec.net/
- **GitHub Discussions**: https://github.com/crowdsecurity/crowdsec/discussions
- **Reddit**: https://www.reddit.com/r/crowdsec/

### Docker and Containerization

- **Docker Compose Documentation**: https://docs.docker.com/compose/
- **Docker Logging Drivers**: https://docs.docker.com/config/containers/logging/
- **Docker Healthcheck**: https://docs.docker.com/engine/reference/builder/#healthcheck
- **Alpine Linux Packages**: https://pkgs.alpinelinux.org/packages

### Shell Scripting

- **POSIX Shell Specification**: https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html
- **BusyBox Documentation**: https://busybox.net/
- **ShellCheck (linter)**: https://www.shellcheck.net/

## Related Projects

### Official CrowdSec Bouncers

- **cs-firewall-bouncer**: iptables/nftables integration
  - GitHub: https://github.com/crowdsecurity/cs-firewall-bouncer

- **cs-cloudflare-bouncer**: Cloudflare firewall rules
  - GitHub: https://github.com/crowdsecurity/cs-cloudflare-bouncer

- **cs-nginx-bouncer**: NGINX/OpenResty integration
  - GitHub: https://github.com/crowdsecurity/cs-nginx-bouncer

### Community Bouncers

- **traefik-crowdsec-bouncer**: Traefik middleware
  - GitHub: https://github.com/fbonalair/traefik-crowdsec-bouncer

- **crowdsec-blocklist-mirror**: Blocklist distribution
  - GitHub: https://github.com/crowdsecurity/cs-blocklist-mirror

### IP Reputation Services (Alternatives to AbuseIPDB)

- **IPSum**: Aggregated threat feeds
  - Website: https://github.com/stamparm/ipsum

- **AlienVault OTX**: Open Threat Exchange
  - Website: https://otx.alienvault.com/

- **Talos Intelligence**: Cisco threat intelligence
  - Website: https://talosintelligence.com/

## Version History and Changelogs

### CrowdSec Releases

- **CrowdSec GitHub Releases**: https://github.com/crowdsecurity/crowdsec/releases
- **Custom Bouncer Releases**: https://github.com/crowdsecurity/cs-custom-bouncer/releases

### AbuseIPDB API Changes

- **API v2 Launch**: November 2018 (deprecated v1)
- **TLS 1.2 Requirement**: January 2023 (deprecated TLS 1.0/1.1)
- **Rate Limit Headers Added**: June 2020 (`X-RateLimit-Remaining`)

## Standards and RFCs

### IP Address Standards

- **RFC 1918**: Address Allocation for Private Internets
  - URL: https://datatracker.ietf.org/doc/html/rfc1918
  - Defines: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

- **RFC 3927**: Dynamic Configuration of IPv4 Link-Local Addresses
  - URL: https://datatracker.ietf.org/doc/html/rfc3927
  - Defines: 169.254.0.0/16

- **RFC 6598**: Shared Address Space (CGNAT)
  - URL: https://datatracker.ietf.org/doc/html/rfc6598
  - Defines: 100.64.0.0/10

### HTTP Standards

- **RFC 7231**: HTTP/1.1 Semantics and Content
  - URL: https://datatracker.ietf.org/doc/html/rfc7231
  - Defines: 401 Unauthorized, 429 Too Many Requests

- **RFC 6585**: Additional HTTP Status Codes
  - URL: https://datatracker.ietf.org/doc/html/rfc6585
  - Defines: 429 Too Many Requests (rate limiting)

## Acknowledgments

This project would not be possible without:

- **CrowdSec Team**: For the excellent threat detection framework and custom-bouncer scaffold
- **AbuseIPDB**: For maintaining the IP reputation database and providing the free API tier
- **Alpine Linux Project**: For the minimal, secure Docker base images
- **jq Contributors**: For the indispensable JSON parsing tool
- **BusyBox Maintainers**: For the POSIX-compliant shell implementation
