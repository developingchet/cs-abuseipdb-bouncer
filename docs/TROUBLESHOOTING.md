# Troubleshooting Guide

Common issues and solutions for the CrowdSec AbuseIPDB Bouncer.

## Table of Contents

- [Container Won't Start](#container-wont-start)
  - [Seccomp profile blocks container startup](#seccomp-profile-blocks-container-startup)
- [No Decisions Being Reported](#no-decisions-being-reported)
- [Authentication Errors](#authentication-errors)
- [Rate Limiting](#rate-limiting)
- [State and Quota Issues](#state-and-quota-issues)
- [Network Connectivity](#network-connectivity)
- [Debug Procedure](#debug-procedure)

---

## Container Won't Start

### Configuration validation error

**Symptom:** Container exits immediately with a configuration error.

```json
{"level":"error","error":"3 configuration error(s):\n  - CROWDSEC_LAPI_KEY is required...","msg":"fatal"}
```

**Cause:** One or more required environment variables are missing or invalid.

**Fix:** Check that `.env` contains all required variables and that it is being read:

```bash
# Verify .env is loaded
docker compose config | grep -E "CROWDSEC|ABUSEIPDB"

# Check for common issues
grep -E "^(CROWDSEC_LAPI_URL|CROWDSEC_LAPI_KEY|ABUSEIPDB_API_KEY)=" .env
```

All three must be set and non-empty. `CROWDSEC_LAPI_URL` must include the scheme (`http://` or `https://`).

### LAPI connection refused at startup

**Symptom:** Container starts but immediately shows a connection error.

```json
{"level":"error","error":"dial tcp: connect: connection refused","msg":"bouncer init failed"}
```

**Cause:** The LAPI URL is unreachable from inside the container.

**Fix:**
1. Verify the LAPI URL is correct: `CROWDSEC_LAPI_URL=http://crowdsec:8080`
2. Verify the bouncer is on the same Docker network as CrowdSec
3. Test connectivity from within the container:

```bash
# For HTTP LAPI
docker exec abuseipdb-bouncer /usr/local/bin/bouncer healthcheck
```

### Volume permission denied at startup

**Symptom:** Container exits immediately on first run.

```json
{"level":"error","error":"open /data/state.db: permission denied","msg":"fatal"}
```

**Cause:** The named volume was created before the image embedded `/data` with the correct ownership. Docker provisioned the volume owned `root:root`; the process (UID 65532) cannot write to it.

**Fix (one-time, only needed for volumes created before this was fixed):**

```bash
# Find your volume name (compose project name prefix + "bouncer-state")
docker volume ls | grep bouncer-state

# Repair ownership — replace <volume-name> with the name above
docker run --rm -v <volume-name>:/data alpine chown 65532:65532 /data

# Restart
docker compose up -d
```

**Fresh installs:** No action required — the image now embeds `/data` owned by UID 65532 and Docker seeds new volumes with that ownership automatically.

### Seccomp profile blocks container startup

**Symptom:** Container crash-loops immediately and logs show one of:

```
error closing exec fds: readdirent fsmount:fscontext:proc/thread-self/fd/: operation not permitted
OCI runtime start failed [...] reopen exec fifo [...] operation not permitted
```

**Why this happens:** Docker's OCI runtime (`runc`) applies the seccomp filter to the container process *before* `execve` hands control to the Go binary. Every syscall runc makes during its own init — enumerating file descriptors in `/proc/thread-self/fd/`, closing them, resolving symlinks, checking capabilities, and finally calling `execve` itself — runs under the filter. If any of those syscalls are absent from the allowlist, the container crashes before the Go binary ever runs.

**Diagnosis:** Run the static validator locally:

```bash
bash scripts/validate-seccomp.sh ./security/seccomp-bouncer.json
```

A `PASS` result means the profile file on disk is correct. If you see `MISS` lines, the host's copy of the profile is outdated.

**Fix:** Download the current profile from GitHub and recreate the container:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/developingchet/cs-abuseipdb-bouncer/main/security/seccomp-bouncer.json \
  -o ./security/seccomp-bouncer.json

docker compose up -d --force-recreate cs-abuseipdb-bouncer
docker logs cs-abuseipdb-bouncer
```

**Note on `close_range`:** This syscall requires Linux 5.9+. On older kernels runc falls back to closing FDs one at a time (`ENOSYS` is handled gracefully), so allowing `close_range` in the profile is safe across all kernel versions — it simply never gets called on kernels that don't support it.

**Prevention:** The CI `test-seccomp` job (`.github/workflows/ci.yml`) runs a fast Alpine container under the profile before every full image build, catching missing syscalls within seconds.

---

## No Decisions Being Reported

### No decisions in CrowdSec

**Symptom:** Bouncer starts successfully but no `reported` log lines appear.

**Check:** Does CrowdSec have any active decisions?

```bash
docker exec crowdsec cscli decisions list
```

If no decisions are listed, the bouncer has nothing to report. Add a test decision:

```bash
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "test"
docker logs -f abuseipdb-bouncer
```

### Decisions are being filtered

**Symptom:** Decisions exist in CrowdSec but the bouncer never reports them. Enable debug logging to see why:

```bash
echo "LOG_LEVEL=debug" >> .env
docker compose up -d --force-recreate abuseipdb-bouncer
docker logs -f abuseipdb-bouncer
```

Look for `"msg":"decision filtered"` log lines. The `filter` field identifies which step rejected the decision:

| filter | Cause | Fix |
|--------|-------|-----|
| `action` | Decision has action=del (delete event) | Normal -- delete events are not reported |
| `scenario-exclude` | impossible-travel scenario | Expected -- these detect account compromise, not IP abuse |
| `origin` | CAPI or lists origin | Expected -- community blocklist IPs are not re-reported |
| `scope` | Range, ASN, or country scope | AbuseIPDB only accepts single IPs |
| `value` | Empty IP value | Indicates a malformed decision in CrowdSec |
| `private-ip` | Private/reserved IP range | Expected -- private IPs are not reported |
| `min-duration` | Decision duration is below ABUSEIPDB_MIN_DURATION | Lower or disable ABUSEIPDB_MIN_DURATION |
| `quota` | Daily limit reached | Wait for UTC midnight reset or increase ABUSEIPDB_DAILY_LIMIT |
| `cooldown` | IP was reported within the cooldown window | Normal -- prevents duplicate reports |

### Decisions are within the cooldown window

If an IP is being repeatedly detected, the first detection is reported and subsequent ones are suppressed until the cooldown expires.

```bash
# Check cooldown file for a specific IP
docker run --rm -v cs-abuseipdb-bouncer_bouncer-state:/state alpine \
  cat /state/cooldown/203_0_113_42
```

The file contains a Unix timestamp (seconds since epoch). Convert it:

```bash
date -d @<timestamp>
```

---

## Authentication Errors

### AbuseIPDB returns 401

**Symptom:**

```json
{"level":"error","error":"unauthorized (401)","ip":"203.0.113.42","msg":"report failed"}
```

**Cause:** The `ABUSEIPDB_API_KEY` value is invalid or the key has been revoked.

**Fix:**
1. Verify the key at https://www.abuseipdb.com/account/api
2. Test the key directly:

```bash
curl -s -w "\nHTTP %{http_code}\n" \
  -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=127.0.0.1" \
  -H "Key: YOUR_KEY" -H "Accept: application/json"
```

If this returns HTTP 401, the key is invalid. Generate a new one and update `.env`.

### CrowdSec LAPI returns 401

**Symptom:** Bouncer logs show LAPI authentication failure at startup.

**Cause:** The `CROWDSEC_LAPI_KEY` has been deleted from CrowdSec.

**Fix:**
1. Check if the bouncer is still registered:

```bash
docker exec crowdsec cscli bouncers list
```

2. If `abuseipdb-bouncer` is missing, re-register:

```bash
docker exec crowdsec cscli bouncers add abuseipdb-bouncer
```

3. Update `CROWDSEC_LAPI_KEY` in `.env` with the new key and restart.

---

## Rate Limiting

### AbuseIPDB returns 429

**Symptom:**

```json
{"level":"warn","sleep":86400,"msg":"rate-limited -- check daily quota at abuseipdb.com/account"}
```

**Cause:** The daily report quota is exhausted. AbuseIPDB enforces this hard limit per API key per day.

**Fix:**
- Wait for the quota to reset. AbuseIPDB resets quotas at 00:00 UTC.
- The bouncer's local `ABUSEIPDB_DAILY_LIMIT` counter prevents most 429 responses by refusing to send reports once the local limit is reached. If you see a 429, the local counter may be lower than the actual AbuseIPDB limit, or the quota was consumed by other means (manual API calls, other tools).
- Lower `ABUSEIPDB_DAILY_LIMIT` to match your actual quota, or upgrade your AbuseIPDB subscription.

---

## State and Quota Issues

### Daily counter not resetting

**Symptom:** Bouncer appears to be at quota limit even after midnight UTC.

**Cause:** The state volume is not mounted, so the counter file is not writable or not accessible.

**Fix:**

```bash
# Check volume mount
docker inspect abuseipdb-bouncer | jq -r '.[0].Mounts'

# Check the daily file
docker run --rm -v cs-abuseipdb-bouncer_bouncer-state:/state alpine cat /state/daily
```

The file format is `"<count> <YYYY-MM-DD>"`. If the date is stale, the bouncer should have reset it automatically on startup. If the file is corrupt, delete it:

```bash
docker run --rm -v cs-abuseipdb-bouncer_bouncer-state:/state alpine rm /state/daily
docker compose restart abuseipdb-bouncer
```

### Cooldown files not pruned

**Symptom:** The cooldown directory grows without bound.

**Cause:** The bouncer prunes cooldown files every 200 decisions and on graceful shutdown. If the container is killed (not stopped) frequently, pruning may not run.

**Fix:** Prune manually:

```bash
# Delete all expired cooldown files
docker run --rm -v cs-abuseipdb-bouncer_bouncer-state:/state alpine \
  find /state/cooldown -type f -delete
```

Then restart the bouncer normally. Active cooldowns will be re-established on the next report.

---

## Network Connectivity

### Cannot reach AbuseIPDB

**Symptom:** All reports fail with network errors.

**Test:**

```bash
# The distroless container has no curl/wget; test from the host
curl -s -o /dev/null -w "%{http_code}" https://api.abuseipdb.com
```

Expected: `200` or `403` (403 is normal for unauthenticated root requests).

If the test fails, the issue is with the host's outbound network, firewall rules, or DNS resolution.

### Cannot reach CrowdSec LAPI

**Test:** Use the built-in healthcheck subcommand:

```bash
docker exec abuseipdb-bouncer /usr/local/bin/bouncer healthcheck
echo "Exit: $?"
```

Exit 0 means connectivity is working. Exit non-zero means the LAPI is unreachable or the API key is invalid.

---

## Debug Procedure

When something is not working and the cause is unclear, follow this procedure in order:

**1. Check container health:**

```bash
docker inspect --format='{{json .State}}' abuseipdb-bouncer | jq '{Status, Running, ExitCode, Health: .Health.Status}'
```

**2. Check logs for errors:**

```bash
docker logs abuseipdb-bouncer 2>&1 | grep '"level":"error"'
docker logs abuseipdb-bouncer 2>&1 | grep '"level":"warn"'
```

**3. Enable debug logging:**

```bash
echo "LOG_LEVEL=debug" >> .env
docker compose up -d --force-recreate abuseipdb-bouncer
docker logs -f abuseipdb-bouncer
```

Debug mode logs every decision (received and filtered). Look for decisions that should be reported but are being filtered.

**4. Inject a test decision:**

```bash
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "debug test"
# Watch for the decision to appear in logs within 30 seconds
docker logs -f abuseipdb-bouncer | grep 203.0.113.42
```

**5. Test connectivity from the bouncer:**

```bash
docker exec abuseipdb-bouncer /usr/local/bin/bouncer healthcheck
echo "Healthcheck exit code: $?"
```

**6. Run the binary version check:**

```bash
docker exec abuseipdb-bouncer /usr/local/bin/bouncer version
```

**7. Check CrowdSec sees the bouncer:**

```bash
docker exec crowdsec cscli bouncers list
```

The `last_pull` column should show a recent timestamp (updated every poll interval).

---

If the problem persists after following these steps, open an issue at https://github.com/developingchet/cs-abuseipdb-bouncer/issues and include:

- Output of `docker logs abuseipdb-bouncer` (sanitize API keys and IPs)
- Output of `docker inspect abuseipdb-bouncer` (sanitize API keys)
- Output of `docker exec crowdsec cscli bouncers list`
- Your Docker and Docker Compose versions
- A description of the expected vs. actual behavior
