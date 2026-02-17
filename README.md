<p align="center">
  <img src="https://github.com/user-attachments/assets/5d195eb7-00aa-4496-91e6-98bb27bbce27" width="843" alt="CrowdSec AbuseIPDB Bouncer Logo" style="max-width: 100%; height: auto;">
</p>

# CrowdSec AbuseIPDB Bouncer

A production-ready CrowdSec custom bouncer that automatically reports malicious IP addresses to AbuseIPDB in real-time.

## Overview

This bouncer integrates CrowdSec's Local API with AbuseIPDB's reporting endpoint to share threat intelligence. When CrowdSec detects malicious activity, the bouncer filters, categorizes, and reports the offending IP to AbuseIPDB's database, contributing to the global IP reputation network.

**Key capabilities:**

- Real-time reporting of CrowdSec decisions to AbuseIPDB
- Intelligent scenario-to-category mapping (covers all 23 AbuseIPDB categories)
- Per-IP cooldown enforcement (15 minutes)
- Daily quota tracking with UTC midnight reset
- Optional pre-check to skip whitelisted IPs
- Exponential backoff retry logic
- State persistence across container restarts
- Structured logging matching CrowdSec's format
- Zero PII in reports (only scenario names transmitted)

## How It Works

```
CrowdSec LAPI (HTTPS)
        |
        | Polls every 30s for new decisions
        v
crowdsec-custom-bouncer (Docker container)
        |
        | Feeds JSON decisions via stdin
        v
abuseipdb-reporter.sh
        |
        | Filters, maps, enforces cooldowns
        v
AbuseIPDB v2 API (/report endpoint)
```

The bouncer polls the CrowdSec Local API every 30 seconds. New decisions are streamed as JSON objects to the reporter script via stdin. The script filters out private IPs, community blocklist entries, and decisions already reported within the last 15 minutes. Eligible IPs are mapped to appropriate AbuseIPDB categories and POSTed to the reporting endpoint.

State is maintained in a Docker volume to track per-IP cooldowns and daily report counts.

## Quick Start

**Prerequisites:**
- Docker with Compose v2
- Running CrowdSec instance with accessible LAPI
- AbuseIPDB account (free tier: 1000 reports/day)

**Steps:**

```bash
# Register bouncer with CrowdSec
docker exec crowdsec cscli bouncers add abuseipdb-reporter
# Copy the printed API key

# Clone repository
git clone https://github.com/developingchet/cs-abuseipdb-bouncer.git
cd cs-abuseipdb-bouncer

# Configure
cp .env.example .env
nano .env  # Add API keys

# Edit LAPI connection settings
nano config/crowdsec-custom-bouncer.yaml.tmpl  # Set api_url
nano docker-compose.yml  # Set extra_hosts for LAPI hostname resolution

# Deploy
docker compose build
docker compose up -d

# Verify
docker logs -f abuseipdb-bouncer
docker exec crowdsec cscli bouncers list
```

Expected log output on successful start:

```
time="2026-02-16T20:00:00Z" level=info msg="config rendered — starting bouncer"
time="2026-02-16T20:00:00Z" level=info msg="Starting crowdsec-custom-bouncer v0.0.19..."
time="2026-02-16T20:00:00Z" level=info msg="reporter started limit=1000 used_today=0 cooldown=900s precheck=false min_duration=0s log_level=info"
```

## Documentation

- **[Setup Guide](docs/SETUP.md)** - Complete installation procedures
- **[Configuration Reference](docs/CONFIGURATION.md)** - All options explained
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions
- **[Design Rationale](docs/DESIGN.md)** - Architecture decisions
- **[External References](docs/REFERENCES.md)** - Links to official documentation

## Repository Structure

```
.
├── config/
│   └── crowdsec-custom-bouncer.yaml.tmpl    # Bouncer configuration template
├── docs/
│   ├── CONFIGURATION.md                      # Complete config reference
│   ├── DESIGN.md                             # Architecture and design decisions
│   ├── REFERENCES.md                         # External documentation links
│   ├── SETUP.md                              # Step-by-step installation
│   └── TROUBLESHOOTING.md                    # Common issues
├── scripts/
│   ├── bouncer-entrypoint.sh                 # Container entrypoint
│   ├── crowdsec-abuseipdb-reporter.sh        # Reporter script
│   └── Dockerfile                            # Image build instructions
├── .env.example                              # Environment variable template
├── .gitignore
├── CONTRIBUTING.md                           # Contribution guidelines
├── docker-compose.yml                        # Docker Compose service definition
├── LICENSE
└── README.md
```

## Configuration Summary

All configuration is via environment variables. Required variables:

```bash
CROWDSEC_ABUSEIPDB_BOUNCER_KEY=<from cscli bouncers add>
ABUSEIPDB_API_KEY=<from abuseipdb.com/account/api>
```

Optional variables:

```bash
ABUSEIPDB_DAILY_LIMIT=1000              # Free=1000, Webmaster=3000, Premium=50000
ABUSEIPDB_PRECHECK=false                # Pre-check /check endpoint (separate quota)
ABUSEIPDB_MIN_DURATION=0                # Skip decisions shorter than N seconds
LOG_LEVEL=info                          # info or debug
```

See [CONFIGURATION.md](docs/CONFIGURATION.md) for complete details.

## Scenario Mapping

CrowdSec scenario names are mapped to AbuseIPDB categories via substring matching. Examples:

| Scenario Pattern | AbuseIPDB Categories | Description |
|------------------|---------------------|-------------|
| `*ssh*` | 22 (SSH), 18 (Brute-Force) | SSH attacks |
| `*sqli*`, `*sql-inj*` | 16 (SQL Injection), 21 (Web App Attack) | SQL injection attempts |
| `*wordpress*`, `*drupal*` | 18, 21 | CMS brute-force and exploitation |
| `*http-dos*`, `*ddos*` | 4 (DDoS Attack) | Denial of service |
| `*appsec*`, `*vpatch*` | 21 | WAF/AppSec detections |
| `*cve*`, `*log4*` | 21, 20 (Exploited Host) | CVE exploitation attempts |

Full mapping table in [CONFIGURATION.md](docs/CONFIGURATION.md#scenario-category-mapping).

## Filtered Scenarios

The following are intentionally excluded from reporting:

- **impossible-travel scenarios** - These detect account compromise via geolocation anomalies, not IP-based abuse
- **CAPI/lists origins** - Community blocklist IPs are not re-reported
- **Private IP addresses** - RFC1918, loopback, link-local, CGNAT ranges
- **Non-IP scopes** - Ranges, ASNs, country-level decisions

## State Persistence

State is stored in `/tmp/cs-abuseipdb` inside the container (mounted as a named volume):

```
/tmp/cs-abuseipdb/
├── daily                     # Daily counter: "count YYYY-MM-DD"
└── cooldown/
    ├── 203_0_113_42          # Per-IP timestamp files
    └── 198_51_100_1
```

The daily counter resets at UTC midnight. Cooldown files are auto-pruned after 15 minutes.

## Logging

Logs are written in logrus-compatible structured format:

```
time="2026-02-16T20:15:30Z" level=info msg="reporting ip=203.0.113.42 id=1234567 scenario=ssh-bf cats=22,18"
time="2026-02-16T20:15:31Z" level=info msg="reported ip=203.0.113.42 daily=15/1000"
```

Debug mode logs every decision including filtered ones:

```bash
# Enable debug logging
echo "LOG_LEVEL=debug" >> .env
docker compose up -d --force-recreate abuseipdb-bouncer
```

## Upgrading

**Script changes only (volume mounts):**

```bash
docker compose restart abuseipdb-bouncer
```

**Dockerfile changes (base image version, dependencies):**

```bash
docker compose build
docker compose up -d abuseipdb-bouncer
```

**Check for upstream bouncer updates:**

```bash
curl -s https://api.github.com/repos/crowdsecurity/cs-custom-bouncer/releases/latest | jq -r '.tag_name'
```

Then update `FROM crowdsecurity/custom-bouncer:vX.Y.Z` in `scripts/Dockerfile`.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas where help is needed:
- Additional scenario pattern mappings
- Integration guides (Kubernetes, Proxmox, Synology)
- Multi-architecture Docker images (ARM, ARM64)
- CI/CD workflows

## License

MIT License. See [LICENSE](LICENSE) for full text.

## Support

- **Issues:** https://github.com/developingchet/cs-abuseipdb-bouncer/issues
- **Discussions:** https://github.com/developingchet/cs-abuseipdb-bouncer/discussions
- **CrowdSec Discord:** https://discord.gg/crowdsec

## Acknowledgments

Built on top of CrowdSec's custom-bouncer framework. Thanks to the CrowdSec team and AbuseIPDB for maintaining the IP reputation database.
