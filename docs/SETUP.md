# Setup Guide

Complete installation procedures for the CrowdSec AbuseIPDB Bouncer.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
- [Step-by-Step Installation](#step-by-step-installation)
- [Post-Installation Verification](#post-installation-verification)
- [Integration Examples](#integration-examples)

## Prerequisites

### System Requirements

- **Docker Engine** - Version 20.10 or higher
- **Docker Compose** - v2.0 or higher (included with modern Docker installations)
- **Operating System** - Linux (tested on Ubuntu 22.04, Debian 11/12, CentOS Stream 9)
- **Network Access** - Outbound HTTPS (port 443) to api.abuseipdb.com
- **Storage** - Minimum 100MB for Docker image and state

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

## Installation Methods

### Method 1: Docker Compose (Recommended)

Best for:
- Running alongside an existing Docker-based CrowdSec deployment
- Easy integration with other containers on the same Docker network
- Automatic restarts and healthchecks

### Method 2: Standalone Docker Container

Best for:
- Minimal installations
- Remote CrowdSec LAPI (not on the same host)
- Custom orchestration tools

This guide covers Method 1. For Method 2, see the standalone example at the end.

## Step-by-Step Installation

### 1. Register the Bouncer with CrowdSec

The bouncer requires an API key to authenticate with the CrowdSec LAPI.

```bash
docker exec crowdsec cscli bouncers add abuseipdb-reporter
```

Output:

```
Api key for 'abuseipdb-reporter':

   xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

Please keep this key since you will not be able to retrieve it!
```

**Copy this key immediately.** You will need it in step 3.

Verify the bouncer was registered:

```bash
docker exec crowdsec cscli bouncers list
```

Expected output includes a row for `abuseipdb-reporter` with `last_pull` showing "never" (it hasn't connected yet).

### 2. Clone the Repository

```bash
cd /opt  # or your preferred location
git clone https://github.com/developingchet/cs-abuseipdb-bouncer.git
cd cs-abuseipdb-bouncer
```

Verify the repository structure:

```bash
tree -L 2
```

Expected output:

```
.
├── config
│   └── crowdsec-custom-bouncer.yaml.tmpl
├── docs
│   ├── CONFIGURATION.md
│   ├── DESIGN.md
│   ├── REFERENCES.md
│   ├── SETUP.md
│   └── TROUBLESHOOTING.md
├── scripts
│   ├── bouncer-entrypoint.sh
│   ├── crowdsec-abuseipdb-reporter.sh
│   └── Dockerfile
├── .env.example
├── .gitignore
├── CONTRIBUTING.md
├── docker-compose.yml
├── LICENSE
└── README.md
```

### 3. Configure Environment Variables

Create the environment file:

```bash
cp .env.example .env
chmod 600 .env  # Restrict permissions (contains API keys)
```

Edit `.env`:

```bash
nano .env  # or vim, code, etc.
```

Fill in the required variables:

```bash
# From step 1
CROWDSEC_ABUSEIPDB_BOUNCER_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# From your AbuseIPDB account
ABUSEIPDB_API_KEY=your_abuseipdb_v2_key_here

# Daily limit based on your tier
ABUSEIPDB_DAILY_LIMIT=1000  # Free tier

# Optional: Enable pre-check to skip whitelisted IPs
# ABUSEIPDB_PRECHECK=false

# Optional: Filter out test/simulation events (decisions shorter than 5 minutes)
# ABUSEIPDB_MIN_DURATION=0

# Log level (info or debug)
LOG_LEVEL=info
```

Save and exit.

Verify the file has no syntax errors:

```bash
source .env && echo "CROWDSEC_ABUSEIPDB_BOUNCER_KEY is set to: ${CROWDSEC_ABUSEIPDB_BOUNCER_KEY:0:8}..."
source .env && echo "ABUSEIPDB_API_KEY is set to: ${ABUSEIPDB_API_KEY:0:8}..."
```

### 4. Configure LAPI Connection

Edit the bouncer configuration template:

```bash
nano config/crowdsec-custom-bouncer.yaml.tmpl
```

Set the `api_url` to your CrowdSec LAPI address.

**Example 1: CrowdSec on the same Docker host**

If CrowdSec is running on the same host with a TLS proxy (Traefik, Nginx, Caddy):

```yaml
api_url: https://crowdsec.yourdomain.com:8443
```

**Example 2: CrowdSec on the same Docker network without TLS**

If CrowdSec is on the same Docker network without a TLS terminator:

```yaml
api_url: http://crowdsec:8080
insecure_skip_verify: true
```

**Example 3: Remote CrowdSec LAPI**

```yaml
api_url: https://remote-crowdsec.example.com:8443
```

If using a self-signed certificate, add:

```yaml
insecure_skip_verify: true
```

**Do not modify the `api_key` line.** It is a template placeholder replaced by the entrypoint script.

Save and exit.

### 5. Configure Docker Networking

Edit `docker-compose.yml`:

```bash
nano docker-compose.yml
```

**a. Set the LAPI hostname resolution**

Locate the `extra_hosts` section:

```yaml
extra_hosts:
  - "YOUR_LAPI_HOST:YOUR_LAPI_IP"
```

Replace with your actual values:

```yaml
# Example: CrowdSec container at 172.18.0.14
extra_hosts:
  - "crowdsec.yourdomain.com:172.18.0.14"

# Or if using container name on same network
extra_hosts:
  - "crowdsec:172.18.0.14"
```

To find your CrowdSec container IP:

```bash
docker inspect crowdsec | jq -r '.[0].NetworkSettings.Networks | to_entries[0].value.IPAddress'
```

**b. Set the Docker network**

Locate the `networks` section at the bottom:

```yaml
networks:
  crowdsec-net:
    external: true
```

Options:

1. **Use your existing CrowdSec network:**

   Find the network name:
   ```bash
   docker inspect crowdsec | jq -r '.[0].NetworkSettings.Networks | keys[0]'
   ```

   Update `docker-compose.yml`:
   ```yaml
   networks:
     your_crowdsec_network_name:
       external: true
   ```

   And in the service definition:
   ```yaml
   abuseipdb-bouncer:
     networks:
       - your_crowdsec_network_name
   ```

2. **Create a new network:**

   If you want a dedicated network, remove `external: true`:
   ```yaml
   networks:
     crowdsec-net:
       driver: bridge
   ```

Save and exit.

### 6. Make Scripts Executable

Ensure the scripts have execute permissions:

```bash
chmod +x scripts/bouncer-entrypoint.sh
chmod +x scripts/crowdsec-abuseipdb-reporter.sh
```

Verify:

```bash
ls -l scripts/*.sh
```

Expected output shows `-rwxr-xr-x` permissions.

### 7. Build the Docker Image

```bash
docker compose build
```

Expected output includes:

```
[+] Building X.Xs (8/8) FINISHED
 => [internal] load build definition from Dockerfile
 => [internal] load .dockerignore
 => [1/2] FROM docker.io/crowdsecurity/custom-bouncer:v0.0.19
 => [2/2] RUN apk add --no-cache jq curl
 => exporting to image
 => => naming to docker.io/library/abuseipdb-bouncer:local
```

Verify the image was created:

```bash
docker images | grep abuseipdb-bouncer
```

Expected output:

```
abuseipdb-bouncer   local   <image_id>   X seconds ago   ~20MB
```

### 8. Start the Bouncer

```bash
docker compose up -d
```

Expected output:

```
[+] Running 1/1
 ✔ Container abuseipdb-bouncer  Started
```

### 9. Verify the Deployment

**a. Check container status:**

```bash
docker ps | grep abuseipdb-bouncer
```

Expected output shows the container in "Up" state.

**b. Check logs:**

```bash
docker logs abuseipdb-bouncer
```

Expected output:

```
time="2026-02-16T20:00:00Z" level=info msg="config rendered — starting bouncer"
time="2026-02-16T20:00:00Z" level=info msg="Starting crowdsec-custom-bouncer v0.0.19-..."
time="2026-02-16T20:00:00Z" level=info msg="Using API key auth"
time="2026-02-16T20:00:00Z" level=info msg="Processing new and deleted decisions . . ."
time="2026-02-16T20:00:00Z" level=info msg="reporter started limit=1000 used_today=0 cooldown=900s precheck=false min_duration=0s log_level=info"
time="2026-02-16T20:00:00Z" level=info msg="deleting 0 decisions"
time="2026-02-16T20:00:00Z" level=info msg="adding X decisions"
```

If you see errors, proceed to the [Troubleshooting section](#troubleshooting).

**c. Verify bouncer is pulling from LAPI:**

```bash
docker exec crowdsec cscli bouncers list
```

Expected output shows `abuseipdb-reporter` with a recent `last_pull` timestamp:

```
 Name                 IP Address  Valid  Last API pull         Type    Version
 abuseipdb-reporter   172.18.0.X  ✔️      2026-02-16T20:00:30Z  custom  v0.0.19
```

### 10. Test with a Manual Decision

Create a test decision to verify end-to-end functionality:

```bash
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "test report"
```

Check the bouncer logs:

```bash
docker logs abuseipdb-bouncer | tail -5
```

Expected output includes:

```
time="..." level=info msg="reporting ip=203.0.113.42 id=XXXXXXX scenario=manual cats=15"
time="..." level=info msg="reported ip=203.0.113.42 daily=1/1000"
```

Verify on AbuseIPDB:

```bash
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=203.0.113.42" \
  -d maxAgeInDays=1 \
  -H "Key: YOUR_ABUSEIPDB_API_KEY" \
  -H "Accept: application/json" | jq -r '.data.totalReports'
```

Should return `1` if the report was successful.

Clean up the test decision:

```bash
docker exec crowdsec cscli decisions delete -i 203.0.113.42
```

## Post-Installation Verification

### Health Check

The container includes a healthcheck. Verify it's passing:

```bash
docker inspect abuseipdb-bouncer | jq -r '.[0].State.Health.Status'
```

Expected output: `healthy`

### State Persistence

Verify the state volume is mounted:

```bash
docker inspect abuseipdb-bouncer | jq -r '.[0].Mounts[] | select(.Destination == "/tmp/cs-abuseipdb") | .Name'
```

Expected output: `abuseipdb-state` or a volume hash.

Check the daily counter file exists:

```bash
docker exec abuseipdb-bouncer cat /tmp/cs-abuseipdb/daily
```

Expected output: `1 2026-02-16` (or current date if you ran the test in step 10).

### Log Rotation

The bouncer logs to Docker's stdout. Configure log rotation via Docker daemon settings.

Edit `/etc/docker/daemon.json`:

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

## Integration Examples

### Example 1: Traefik with Let's Encrypt

If CrowdSec's LAPI is exposed via Traefik with a real Let's Encrypt certificate:

**docker-compose.yml:**

```yaml
extra_hosts:
  - "crowdsec.yourdomain.com:172.18.0.11"  # Traefik container IP

networks:
  traefik-net:
    external: true
```

**config/crowdsec-custom-bouncer.yaml.tmpl:**

```yaml
api_url: https://crowdsec.yourdomain.com:8443
# No insecure_skip_verify needed — valid certificate
```

### Example 2: Remote CrowdSec LAPI (Different Host)

If CrowdSec is running on a different server:

**docker-compose.yml:**

```yaml
# No extra_hosts needed — use DNS
networks:
  default:
    driver: bridge
```

**config/crowdsec-custom-bouncer.yaml.tmpl:**

```yaml
api_url: https://crowdsec-server.example.com:8443
# Add insecure_skip_verify: true if using self-signed cert
```

Ensure firewall rules allow the bouncer host to reach the LAPI port.

### Example 3: Kubernetes Deployment

For Kubernetes, see the Helm chart in the `k8s/` directory (community contribution).

## Troubleshooting

If issues arise during setup, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common problems and solutions.

Quick diagnostics:

```bash
# Check bouncer can reach LAPI
docker exec abuseipdb-bouncer wget -O- https://crowdsec.yourdomain.com:8443/health

# Check bouncer can reach AbuseIPDB
docker exec abuseipdb-bouncer wget -O- https://api.abuseipdb.com

# Enable debug logging
echo "LOG_LEVEL=debug" >> .env
docker compose up -d --force-recreate abuseipdb-bouncer
docker logs -f abuseipdb-bouncer
```

## Next Steps

- Review [CONFIGURATION.md](CONFIGURATION.md) for advanced configuration options
- Set up log aggregation (Loki, Elasticsearch, Splunk)
- Configure monitoring/alerting on the daily quota metric
- Consider enabling `ABUSEIPDB_PRECHECK` to reduce wasted quota on whitelisted IPs
