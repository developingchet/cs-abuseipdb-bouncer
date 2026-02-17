# Troubleshooting Guide

Common issues and solutions for the CrowdSec AbuseIPDB Bouncer.

## Table of Contents

- [Bouncer Connectivity Issues](#bouncer-connectivity-issues)
- [No Reports Being Sent](#no-reports-being-sent)
- [State Persistence Problems](#state-persistence-problems)
- [Performance Issues](#performance-issues)
- [Log Analysis](#log-analysis)

## Bouncer Connectivity Issues

### Bouncer Cannot Reach LAPI

**Symptoms:**

```
time="..." level=error msg="dial tcp: lookup crowdsec.local: no such host"
time="..." level=error msg="dial tcp 172.18.0.14:8443: connect: connection refused"
time="..." level=error msg="Get https://crowdsec.local:8443/v1/decisions/stream: x509: certificate signed by unknown authority"
```

**Diagnosis:**

1. Check hostname resolution:
   ```bash
   docker exec abuseipdb-bouncer nslookup crowdsec.local
   docker exec abuseipdb-bouncer ping -c 1 crowdsec.local
   ```

2. Verify LAPI is listening:
   ```bash
   docker exec crowdsec netstat -tlnp | grep 8443
   ```

3. Test LAPI from bouncer container:
   ```bash
   docker exec abuseipdb-bouncer wget -O- https://crowdsec.local:8443/health
   ```

**Solutions:**

**DNS resolution failure:**
- Verify `extra_hosts` in `docker-compose.yml` has the correct IP
- Check the LAPI container IP:
  ```bash
  docker inspect crowdsec | jq -r '.[0].NetworkSettings.Networks | to_entries[0].value.IPAddress'
  ```
- Update `docker-compose.yml` and restart:
  ```bash
  docker compose up -d --force-recreate abuseipdb-bouncer
  ```

**Connection refused:**
- LAPI is not listening on the expected port
- Check CrowdSec config:
  ```bash
  docker exec crowdsec cat /etc/crowdsec/config.yaml | grep -A5 api:
  ```
- Update `api_url` in `config/crowdsec-custom-bouncer.yaml.tmpl` to match
- If using TLS via Traefik/Nginx, ensure the proxy is running:
  ```bash
  docker ps | grep traefik
  curl -k https://crowdsec.local:8443/health
  ```

**Certificate error:**
- Using self-signed certificate without `insecure_skip_verify: true`
- Add to `config/crowdsec-custom-bouncer.yaml.tmpl`:
  ```yaml
  insecure_skip_verify: true
  ```
- Rebuild and restart:
  ```bash
  docker compose up -d --force-recreate abuseipdb-bouncer
  ```

### Bouncer Registered but Not Pulling

**Symptoms:**

```bash
docker exec crowdsec cscli bouncers list
# Shows "abuseipdb-reporter" but last_pull is "never" or stale
```

**Diagnosis:**

1. Check bouncer logs for errors:
   ```bash
   docker logs abuseipdb-bouncer | grep -i error
   ```

2. Verify API key is correct:
   ```bash
   # Check key is set (shows first 8 chars)
   docker exec abuseipdb-bouncer env | grep CROWDSEC_ABUSEIPDB_BOUNCER_KEY
   ```

3. Test LAPI manually with the key:
   ```bash
   docker exec crowdsec cscli bouncers list -o json | jq -r '.[] | select(.name=="abuseipdb-reporter") | .token'
   # Use the token from above
   curl -H "X-Api-Key: YOUR_TOKEN" https://crowdsec.local:8443/v1/decisions/stream
   ```

**Solutions:**

**Wrong API key:**
- Regenerate bouncer key:
  ```bash
  docker exec crowdsec cscli bouncers delete abuseipdb-reporter
  docker exec crowdsec cscli bouncers add abuseipdb-reporter
  ```
- Update `.env` with new key
- Restart:
  ```bash
  docker compose up -d --force-recreate abuseipdb-bouncer
  ```

**Bouncer not running:**
- Check container status:
  ```bash
  docker ps -a | grep abuseipdb-bouncer
  ```
- If exited, check logs:
  ```bash
  docker logs abuseipdb-bouncer
  ```
- Common causes: missing environment variables, script syntax errors

### Bouncer Cannot Reach AbuseIPDB

**Symptoms:**

```
time="..." level=error msg="network error connecting to AbuseIPDB ip=..."
```

**Diagnosis:**

1. Test connectivity from container:
   ```bash
   docker exec abuseipdb-bouncer wget -O- https://api.abuseipdb.com
   ```

2. Check for HTTP proxy environment variables:
   ```bash
   docker exec abuseipdb-bouncer env | grep -i proxy
   ```

3. Test DNS resolution:
   ```bash
   docker exec abuseipdb-bouncer nslookup api.abuseipdb.com
   ```

**Solutions:**

**Firewall blocking outbound HTTPS:**
- Allow outbound connections to api.abuseipdb.com on port 443
- If behind corporate proxy, set in `docker-compose.yml`:
  ```yaml
  environment:
    - https_proxy=http://proxy.company.com:8080
  ```

**DNS resolution failure:**
- Use a public DNS server:
  ```yaml
  services:
    abuseipdb-bouncer:
      dns:
        - 8.8.8.8
        - 8.8.4.4
  ```

## No Reports Being Sent

### All Decisions Filtered

**Symptoms:**

```
time="..." level=info msg="reporter started limit=1000 used_today=0 ..."
time="..." level=info msg="adding 5 decisions"
# No "reporting ip=..." lines follow
```

**Diagnosis:**

Enable debug logging to see why decisions are skipped:

```bash
echo "LOG_LEVEL=debug" >> .env
docker compose up -d --force-recreate abuseipdb-bouncer
docker logs -f abuseipdb-bouncer
```

Look for debug messages like:
```
time="..." level=debug msg="skip cooldown ip=..."
time="..." level=debug msg="skip private ip=..."
time="..." level=debug msg="skip origin=CAPI ip=..."
```

**Solutions:**

**All IPs on cooldown:**
- Expected if the decisions are recent (within last 15 minutes)
- Wait 15 minutes and new attacks will be reported
- Check cooldown state:
  ```bash
  docker exec abuseipdb-bouncer ls -lh /tmp/cs-abuseipdb/cooldown/
  ```

**All IPs are private:**
- Decision IPs are RFC1918/loopback/CGNAT
- This is correct behavior (private IPs should not be reported)
- Verify with:
  ```bash
  docker exec crowdsec cscli decisions list -o json | jq -r '.[].value'
  ```

**All origins are CAPI/lists:**
- Decisions are from community blocklist, not local detections
- This is correct behavior (don't re-report community IPs)
- Verify with:
  ```bash
  docker exec crowdsec cscli decisions list -o json | jq -r 'group_by(.origin) | map({origin: .[0].origin, count: length})'
  ```
- To see local detections only:
  ```bash
  docker exec crowdsec cscli decisions list -o json | jq '.[] | select(.origin == "crowdsec" or .origin == "cscli")'
  ```

**Wrong scope:**
- Decisions are Range/AS/Country, not Ip
- Check scopes:
  ```bash
  docker exec crowdsec cscli decisions list -o json | jq -r 'group_by(.scope) | map({scope: .[0].scope, count: length})'
  ```
- The bouncer only processes Ip scope by design

### Daily Quota Exhausted

**Symptoms:**

```
time="..." level=warning msg="daily cap reached limit=1000 dropping ip=..."
```

**Diagnosis:**

Check how many reports were sent today:

```bash
docker exec abuseipdb-bouncer cat /tmp/cs-abuseipdb/daily
# Output: "850 2026-02-16" (count and date)
```

**Solutions:**

**Upgrade AbuseIPDB tier:**
- Webmaster (free): 3000/day - verify domain at https://www.abuseipdb.com/account/webmasters
- Premium (paid): 50000/day

**Increase limit in .env:**
```bash
ABUSEIPDB_DAILY_LIMIT=3000
```

**Filter low-value decisions:**
Set minimum duration to only report long bans:
```bash
ABUSEIPDB_MIN_DURATION=3600  # Only report bans 1 hour or longer
```

Enable pre-check to skip known-good IPs:
```bash
ABUSEIPDB_PRECHECK=true
```

### API Key Invalid

**Symptoms:**

```
time="..." level=error msg="401 unauthorized — verify ABUSEIPDB_API_KEY in .env"
```

**Diagnosis:**

Test API key manually:

```bash
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=127.0.0.1" \
  -d maxAgeInDays=90 \
  -H "Key: YOUR_API_KEY" \
  -H "Accept: application/json"
```

If you get `401 Unauthorized`, the key is invalid.

**Solutions:**

- Verify the key at https://www.abuseipdb.com/account/api
- Generate a new key if needed
- Update `.env`:
  ```bash
  ABUSEIPDB_API_KEY=new_key_here
  ```
- Restart:
  ```bash
  docker compose up -d --force-recreate abuseipdb-bouncer
  ```

## State Persistence Problems

### Daily Counter Resets on Restart

**Symptoms:**

After `docker compose restart`, the daily counter is back to 0.

**Diagnosis:**

Check if the volume is actually mounted:

```bash
docker inspect abuseipdb-bouncer | jq -r '.[0].Mounts[] | select(.Destination == "/tmp/cs-abuseipdb")'
```

If output is empty, the volume is not mounted.

**Solutions:**

Verify `docker-compose.yml` has the volume:

```yaml
volumes:
  - abuseipdb-state:/tmp/cs-abuseipdb
```

And the named volume is defined at the bottom:

```yaml
volumes:
  abuseipdb-state:
    driver: local
```

Recreate:

```bash
docker compose down
docker compose up -d
```

### Cooldown Not Working

**Symptoms:**

Same IP is reported multiple times within 15 minutes.

**Diagnosis:**

1. Check if state directory is writable:
   ```bash
   docker exec abuseipdb-bouncer touch /tmp/cs-abuseipdb/test
   docker exec abuseipdb-bouncer rm /tmp/cs-abuseipdb/test
   ```

2. Check cooldown files are being created:
   ```bash
   docker exec abuseipdb-bouncer ls -lh /tmp/cs-abuseipdb/cooldown/
   ```

3. Look for log entries:
   ```bash
   docker logs abuseipdb-bouncer | grep "skip cooldown"
   ```

**Solutions:**

**Volume permissions issue:**
- Recreate the volume:
  ```bash
  docker compose down -v
  docker compose up -d
  ```

**Multiple bouncer instances:**
- If running multiple containers with separate volumes, each tracks cooldowns independently
- Use a shared volume across instances:
  ```yaml
  services:
    bouncer-1:
      volumes:
        - abuseipdb-state:/tmp/cs-abuseipdb
    bouncer-2:
      volumes:
        - abuseipdb-state:/tmp/cs-abuseipdb  # Same volume
  ```

## Performance Issues

### High Memory Usage

**Symptoms:**

Container using more than 100MB RAM.

**Diagnosis:**

Check memory usage:

```bash
docker stats abuseipdb-bouncer --no-stream
```

**Typical usage:** 20-50MB

**Solutions:**

**Large number of cooldown files:**
- Check count:
  ```bash
  docker exec abuseipdb-bouncer find /tmp/cs-abuseipdb/cooldown -type f | wc -l
  ```
- If over 10,000, there may be a cleanup issue
- Manually prune:
  ```bash
  docker exec abuseipdb-bouncer find /tmp/cs-abuseipdb/cooldown -type f -mmin +15 -delete
  ```

**jq/curl memory leak (rare):**
- Restart the container:
  ```bash
  docker compose restart abuseipdb-bouncer
  ```

### Slow Reporting

**Symptoms:**

Long delays between "reporting ip=..." and "reported ip=...".

**Diagnosis:**

Time an API call:

```bash
time docker exec abuseipdb-bouncer curl -X POST https://api.abuseipdb.com/api/v2/report \
  -H "Key: YOUR_KEY" \
  --data-urlencode "ip=203.0.113.42" \
  --data-urlencode "categories=15" \
  --data-urlencode "comment=test"
```

**Typical response time:** 200-500ms

**Solutions:**

**Network latency:**
- Check latency to AbuseIPDB:
  ```bash
  docker exec abuseipdb-bouncer ping -c 10 api.abuseipdb.com
  ```
- If high (>100ms), consider geographic CDN or accept the delay

**Rate limiting (429):**
- Look for warning logs:
  ```
  time="..." level=warning msg="rate-limited sleep=..."
  ```
- This is expected when hitting quota limits
- Reduce decision volume or upgrade tier

## Log Analysis

### Structured Log Parsing

The logs use logrus format: `time="..." level=... msg="..."`

**Extract all errors:**

```bash
docker logs abuseipdb-bouncer | grep 'level=error'
```

**Count reports by category:**

```bash
docker logs abuseipdb-bouncer \
  | grep 'reporting ip=' \
  | grep -oP 'cats=\K[0-9,]+' \
  | sort | uniq -c | sort -rn
```

**Daily report count:**

```bash
docker logs abuseipdb-bouncer \
  | grep 'reported ip=' \
  | grep -oP 'daily=\K[0-9]+' \
  | tail -1
```

**Most reported IPs:**

```bash
docker logs abuseipdb-bouncer \
  | grep 'reported ip=' \
  | grep -oP 'reported ip=\K[0-9.]+' \
  | sort | uniq -c | sort -rn | head -10
```

### Debug Mode Analysis

With `LOG_LEVEL=debug`, analyze why decisions are filtered:

**Cooldown hits:**

```bash
docker logs abuseipdb-bouncer | grep 'skip cooldown' | wc -l
```

**Private IP filters:**

```bash
docker logs abuseipdb-bouncer | grep 'skip private' | wc -l
```

**Origin filters:**

```bash
docker logs abuseipdb-bouncer | grep 'skip origin=' | grep -oP 'origin=\K[^ ]+' | sort | uniq -c
```

## Getting Help

If issues persist after trying these solutions:

1. Collect diagnostic information:
   ```bash
   docker logs abuseipdb-bouncer > bouncer.log
   docker inspect abuseipdb-bouncer > bouncer-inspect.json
   docker exec crowdsec cscli bouncers list -o json > bouncers.json
   docker exec crowdsec cscli decisions list -o json > decisions.json
   ```

2. Open an issue at https://github.com/developingchet/cs-abuseipdb-bouncer/issues

3. Include:
   - Output of `docker logs abuseipdb-bouncer` (sanitize IPs/keys)
   - Output of `docker compose config` (sanitize keys)
   - CrowdSec version: `docker exec crowdsec cscli version`
   - Description of expected vs actual behavior

4. Join CrowdSec Discord for community support: https://discord.gg/crowdsec
