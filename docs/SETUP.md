# Setup Guide

Complete installation procedures for the CrowdSec AbuseIPDB Bouncer.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step-by-Step Installation](#step-by-step-installation)
- [Post-Installation Verification](#post-installation-verification)
- [Integration Examples](#integration-examples)

## Prerequisites

### System Requirements

- **Docker Engine** - Version 20.10 or higher
- **Docker Compose** - v2.0 or higher (included with modern Docker installations)
- **Operating System** - Linux (tested on Ubuntu 22.04, Debian 11/12, CentOS Stream 9)
- **Network Access** - Outbound HTTPS (port 443) to api.abuseipdb.com
- **Storage** - Minimum 50MB for Docker image and state volume

### CrowdSec Requirements

- **CrowdSec** - Version 1.4.0 or higher
- **LAPI Access** - Network access to the Local API (default port 8080 or 8443 if TLS-enabled)
- **Admin Privileges** - Ability to run `cscli bouncers add`

Verify CrowdSec is running:

```bash
docker exec crowdsec cscli version
docker exec crowdsec cscli lapi status
```

### AbuseIPDB Requirements

- **Account** - Free account at https://www.abuseipdb.com/register
- **API Key** - v2 API key from https://www.abuseipdb.com/account/api
- **Quota** - Daily limit: Free=1000, Webmaster=3000, Premium=50000

Verify your API key works:

```bash
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=127.0.0.1" \
  -d maxAgeInDays=90 \
  -H "Key: YOUR_API_KEY" \
  -H "Accept: application/json"
```

Expected response includes `"data":{"ipAddress":"127.0.0.1",...}`.

---

## Step-by-Step Installation

### 1. Register the Bouncer with CrowdSec

The bouncer authenticates to the LAPI with a per-bouncer API key.

```bash
docker exec crowdsec cscli bouncers add abuseipdb-bouncer
```

Output:

```
Api key for 'abuseipdb-bouncer':

   xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

Please keep this key since you will not be able to retrieve it!
```

**Copy this key immediately.** You will need it in step 3.

Verify the bouncer was registered:

```bash
docker exec crowdsec cscli bouncers list
```

The output should include a row for `abuseipdb-bouncer` with `last_pull` showing "never" (it has not connected yet).

### 2. Clone the Repository

```bash
cd /opt  # or your preferred location
git clone https://github.com/developingchet/cs-abuseipdb-bouncer.git
cd cs-abuseipdb-bouncer
```

### 3. Configure Environment Variables

```bash
cp .env.example .env
chmod 600 .env  # Restrict permissions -- file contains API keys
nano .env       # or vim, code, etc.
```

Minimum required configuration:

```bash
# CrowdSec LAPI connection
CROWDSEC_LAPI_URL=http://crowdsec:8080   # Adjust for your LAPI address
CROWDSEC_LAPI_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  # From step 1

# AbuseIPDB
ABUSEIPDB_API_KEY=your_abuseipdb_v2_key_here
```

Optional configuration (uncomment and adjust as needed):

```bash
# ABUSEIPDB_DAILY_LIMIT=1000    # Match your subscription tier
# ABUSEIPDB_PRECHECK=false      # Enable to skip whitelisted IPs
# ABUSEIPDB_MIN_DURATION=0      # Set to 300 to skip test decisions
# COOLDOWN_DURATION=15m         # Per-IP cooldown window
# LOG_LEVEL=info                # debug for verbose output
```

Save and verify:

```bash
source .env
echo "CROWDSEC_LAPI_KEY prefix: ${CROWDSEC_LAPI_KEY:0:8}..."
echo "ABUSEIPDB_API_KEY prefix: ${ABUSEIPDB_API_KEY:0:8}..."
```

### 4. Configure Docker Networking

The bouncer needs network access to the CrowdSec LAPI. Edit `docker-compose.yml` and set the correct network name.

**Find your CrowdSec Docker network:**

```bash
docker inspect crowdsec | jq -r '.[0].NetworkSettings.Networks | keys[0]'
```

**Update docker-compose.yml:**

```yaml
networks:
  your_actual_network_name:   # Replace crowdsec-net with the name above
    external: true
```

And in the service `networks` list:

```yaml
abuseipdb-bouncer:
  networks:
    - your_actual_network_name
```

If CrowdSec is on a different host (remote LAPI), set `CROWDSEC_LAPI_URL` to the full HTTPS address and leave the networks section using the default bridge:

```yaml
networks:
  crowdsec-net:
    driver: bridge
```

### 5. Build the Docker Image

```bash
docker compose build
```

This step downloads Go module dependencies and compiles the binary inside the container. No local Go installation is required.

Expected output:

```
[+] Building X.Xs (8/8) FINISHED
 => [builder 1/5] FROM docker.io/library/golang:1.23-alpine
 => [builder 4/5] RUN go mod download
 => [builder 5/5] RUN CGO_ENABLED=0 ... go build -o /bouncer ./cmd/bouncer/
 => [stage-1 1/4] FROM gcr.io/distroless/static-debian12:nonroot
 => exporting to image
```

Verify the image:

```bash
docker images | grep abuseipdb-bouncer
```

The final image is approximately 8-12MB.

### 6. Start the Bouncer

```bash
docker compose up -d
```

Expected output:

```
[+] Running 1/1
 ✔ Container abuseipdb-bouncer  Started
```

### 7. Verify the Deployment

**Check container status:**

```bash
docker ps | grep abuseipdb-bouncer
```

Expected: container in "Up" state with `(healthy)` once the healthcheck passes (~15 seconds after startup).

**Check startup logs:**

```bash
docker logs abuseipdb-bouncer
```

Expected startup log:

```json
{"time":1739836200,"level":"info","limit":1000,"used_today":0,"cooldown":"15m0s","precheck":false,"min_duration":"0s","log_level":"info","msg":"bouncer started"}
```

**Verify the bouncer is pulling from LAPI:**

```bash
docker exec crowdsec cscli bouncers list
```

Expected: `abuseipdb-bouncer` row shows a recent `last_pull` timestamp.

### 8. Test with a Manual Decision

```bash
# Create a test decision (203.0.113.42 is the TEST-NET-3 documentation range)
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "test report"

# Watch logs
docker logs -f abuseipdb-bouncer
```

Expected log output:

```json
{"time":1739836530,"level":"info","ip":"203.0.113.42","sink":"abuseipdb","daily":1,"limit":1000,"msg":"reported"}
```

Verify on AbuseIPDB:

```bash
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=203.0.113.42" \
  -d maxAgeInDays=1 \
  -H "Key: YOUR_ABUSEIPDB_API_KEY" \
  -H "Accept: application/json" | jq -r '.data.totalReports'
```

Should return `1` if the report succeeded.

Clean up the test decision:

```bash
docker exec crowdsec cscli decisions delete -i 203.0.113.42
```

---

## Post-Installation Verification

### Health Check

The container has a built-in healthcheck that runs `bouncer healthcheck` every 30 seconds. This performs a lightweight connectivity check against the AbuseIPDB API.

```bash
docker inspect abuseipdb-bouncer | jq -r '.[0].State.Health.Status'
```

Expected: `healthy`

### State Persistence

Verify the named volume is mounted:

```bash
docker inspect abuseipdb-bouncer | jq -r '.[0].Mounts[] | select(.Destination == "/data") | .Name'
```

Verify the state database exists:

```bash
docker run --rm -v cs-abuseipdb-bouncer_bouncer-state:/state alpine ls -lh /state/state.db
```

Expected: `state.db` is present after the first LAPI poll cycle (absent on a completely fresh install with zero decisions processed).

### Log Rotation

Configure Docker's log driver to prevent unbounded log growth. Edit `/etc/docker/daemon.json`:

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

Restart Docker:

```bash
sudo systemctl restart docker
```

---

## Integration Examples

### Example 1: TLS-Enabled LAPI

If CrowdSec's LAPI uses a valid TLS certificate (via Traefik, Nginx, or Caddy):

```bash
# .env
CROWDSEC_LAPI_URL=https://crowdsec.yourdomain.com:8443
```

No other changes are needed -- the container includes standard CA certificates from the Alpine builder stage.

### Example 2: Self-Signed Certificate

If your LAPI uses a self-signed certificate:

```bash
# .env
CROWDSEC_LAPI_URL=https://crowdsec.local:8443
TLS_SKIP_VERIFY=true
```

### Example 3: Remote LAPI on a Different Host

If CrowdSec runs on a separate machine:

```bash
# .env
CROWDSEC_LAPI_URL=https://crowdsec-server.example.com:8443
```

Update `docker-compose.yml` to use the default bridge network (no `external: true`):

```yaml
networks:
  crowdsec-net:
    driver: bridge
```

Ensure your firewall allows the bouncer host to reach the LAPI port (8080 or 8443).

### Example 4: CrowdSec on the Same Docker Network

If the bouncer and CrowdSec containers are on the same Docker network, Docker DNS resolves the service name automatically:

```bash
# .env
CROWDSEC_LAPI_URL=http://crowdsec:8080
```

No `extra_hosts` entry is needed.

### Example 5: Kubernetes Deployment

Kubernetes support is not included in this repository. If you need a Helm chart or Kubernetes manifests, open a discussion at https://github.com/developingchet/cs-abuseipdb-bouncer/discussions -- community contributions are welcome.

---

## Troubleshooting

If issues arise, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common problems and solutions.

Quick diagnostics:

```bash
# Check container health
docker inspect --format='{{.State.Health.Status}}' abuseipdb-bouncer

# Enable debug logging
echo "LOG_LEVEL=debug" >> .env
docker compose up -d --force-recreate abuseipdb-bouncer
docker logs -f abuseipdb-bouncer

# Run healthcheck manually
docker exec abuseipdb-bouncer /usr/local/bin/bouncer healthcheck
echo "Exit code: $?"
```

## Next Steps

- Review [CONFIGURATION.md](CONFIGURATION.md) for all available options
- Set up log aggregation (Loki, Elasticsearch, Splunk)
- Configure monitoring or alerting on daily quota usage
- Consider enabling `ABUSEIPDB_PRECHECK=true` to reduce wasted quota on whitelisted IPs
