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

**Symptom:** The container stays up but logs LAPI connection errors every 10 seconds, and turns `unhealthy` about two minutes after start.

```json
{"level":"error","component":"lapi-client","message":"failed to connect to LAPI, retrying in 10s: Get \"http://crowdsec:8080/v1/decisions/stream?...\": dial tcp 172.18.0.2:8080: connect: connection refused"}
```

**Cause:** The LAPI URL is unreachable from inside the container (or CrowdSec is still starting — the bouncer keeps retrying until it comes up).

**Fix:**
1. Verify the LAPI URL is correct: `CROWDSEC_LAPI_URL=http://crowdsec:8080`
2. Verify the bouncer is on the same Docker network as CrowdSec
3. Ask the bouncer for its status:

```bash
docker exec abuseipdb-bouncer /usr/local/bin/bouncer healthcheck
# {"status":"unhealthy","reason":"no successful LAPI pull since startup 3m10s ago",...}
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

Look for `"message":"decision filtered (pre-queue)"` and `"decision filtered (cooldown|quota)"` log lines. The `filter` field (and the `filter` label on `cs_abuseipdb_decisions_skipped_total`) identifies which step rejected the decision:

| filter | Cause | Fix |
|--------|-------|-----|
| `action` | Decision has action=del (delete event) | Normal -- delete events are not reported |
| `scenario_exclude` | impossible-travel scenario | Expected -- these detect account compromise, not IP abuse |
| `origin` | CAPI or lists origin | Expected -- community blocklist IPs are not re-reported |
| `scope` | Range, ASN, or country scope | AbuseIPDB only accepts single IPs |
| `value` | Empty IP value | Indicates a malformed decision in CrowdSec |
| `private_ip` | Private/reserved IP range | Expected -- private IPs are not reported |
| `whitelist` | IP is in `IP_WHITELIST` | Expected — trusted range you configured |
| `min_duration` | Decision duration is below ABUSEIPDB_MIN_DURATION | Lower or disable ABUSEIPDB_MIN_DURATION |
| `quota` | Daily limit reached | Wait for UTC midnight reset or increase ABUSEIPDB_DAILY_LIMIT |
| `cooldown` | IP was reported within the cooldown window | Normal -- prevents duplicate reports |
| `duplicate` | AbuseIPDB rejected a repeat report within its 15-minute window | Normal; keep `COOLDOWN_DURATION` ≥ 15m to avoid the wasted call |
| `rejected` | AbuseIPDB returned 422 (invalid parameters) | Check the `detail` in the error log line |
| `retry_exhausted` | Report failed 6 times in a row | Check AbuseIPDB reachability / API key |
| `buffer_full` | Worker queue full during a burst | Increase `WORKER_BUFFER` or `WORKER_COUNT` |

### Decisions are within the cooldown window

If an IP is being repeatedly detected, the first detection is reported and subsequent ones are suppressed until the cooldown expires. Cooldowns live in the `cooldown` bucket of `state.db`. Enable `LOG_LEVEL=debug` to see `decision filtered (cooldown)` lines rather than inspecting the database: `state.db` cannot be opened while the bouncer is running (bbolt holds an exclusive lock).

---

## Authentication Errors

### AbuseIPDB returns 401

**Symptom:**

```json
{"level":"error","message":"401 unauthorized -- verify ABUSEIPDB_API_KEY"}
{"level":"error","error":"unauthorized: upstream rejected the API key (401)","sink":"abuseipdb","ip":"203.0.113.42","message":"report failed"}
```

After 5 consecutive failures `/healthz` reports unhealthy. Affected decisions are kept in the retry queue (up to 6 attempts with backoff), so reports resume once the key is fixed and the container restarted.

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

**Symptom:** Bouncer logs show repeated `"component":"lapi-client"` errors mentioning 403/401, and the container turns unhealthy.

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
{"level":"warn","ip":"203.0.113.42","retry_after":3600000,"detail":"Daily rate limit of 1000 requests exceeded for this endpoint. See headers for additional details.","message":"rate-limited -- decision queued for retry"}
```

**Cause:** The daily report quota is exhausted. AbuseIPDB enforces this hard limit per API key per day.

**What the bouncer does:** the decision is persisted to the retry queue and resent after the `Retry-After` / `X-RateLimit-Reset` time AbuseIPDB returns. Rate limits do not make the container unhealthy.

A 429 whose detail says *"You can only report the same IP address … once in 15 minutes"* is a duplicate, not a quota problem; it is dropped (`filter="duplicate"`) and logged at debug level only.

**Fix:**
- Wait for the quota to reset. AbuseIPDB resets quotas at 00:00 UTC.
- The bouncer's local `ABUSEIPDB_DAILY_LIMIT` counter prevents most 429 responses by refusing to send reports once the local limit is reached. If you see a 429, the local counter may be lower than the actual AbuseIPDB limit, or the quota was consumed by other means (manual API calls, other tools).
- Lower `ABUSEIPDB_DAILY_LIMIT` to match your actual quota, or upgrade your AbuseIPDB subscription.

---

## State and Quota Issues

### Daily counter not resetting

**Symptom:** Bouncer appears to be at quota limit even after midnight UTC.

**Cause:** The quota record (`quota` bucket in `state.db`) stores its UTC date and resets itself on the first report of a new UTC day. A stuck counter usually means you are comparing against AbuseIPDB's own counter, or the host clock is wrong.

**Check:**

```bash
curl -s http://127.0.0.1:9090/metrics | grep cs_abuseipdb_quota_remaining
date -u   # host clock
```

**Reset all state (last resort):** stop the bouncer first — `state.db` is exclusively locked while it runs — then remove the volume:

```bash
docker compose stop abuseipdb-bouncer
docker volume rm cs-abuseipdb-bouncer_bouncer-state
docker compose up -d abuseipdb-bouncer
```

This clears the quota counter, all cooldowns and the retry queue.

### state.db keeps growing

**Symptom:** `cs_abuseipdb_bbolt_db_size_bytes` rises steadily.

**Cause:** The janitor prunes expired cooldowns and stale retry entries every `JANITOR_INTERVAL` (default 5m); bbolt reuses freed pages but does not shrink the file. Steady growth usually means a very long `COOLDOWN_DURATION` with many distinct IPs, or a large retry queue (`cs_abuseipdb_retry_queue_size`) during a long AbuseIPDB outage.

**Fix:** Check the retry queue size and AbuseIPDB connectivity first. To reclaim disk space, reset the volume as described above.

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

**Test:** Use the built-in healthcheck subcommand, which asks the running bouncer (via `/healthz`) when it last polled LAPI successfully:

```bash
docker exec abuseipdb-bouncer /usr/local/bin/bouncer healthcheck
echo "Exit: $?"
```

Exit 0 prints `{"status":"ok","last_lapi_pull":...}`. A non-zero exit prints the reason, e.g. `last successful LAPI pull was 6m0s ago`; the matching errors are in `docker logs` with `"component":"lapi-client"`. You can also check `cscli bouncers list` on the CrowdSec side (`last_pull` column).

### Container shows `unhealthy`

The Docker `HEALTHCHECK` calls `bouncer healthcheck`, which GETs `/healthz` on `METRICS_ADDR`. See why:

```bash
docker inspect --format '{{json .State.Health}}' abuseipdb-bouncer | jq '.Log[-1].Output'
```

| Output contains | Meaning |
|-----------------|---------|
| `no successful LAPI pull since startup` / `last successful LAPI pull was` | LAPI unreachable or key rejected — see above |
| `last 5 AbuseIPDB calls failed` | Network/TLS problem reaching api.abuseipdb.com, AbuseIPDB 5xx, or invalid API key (401) |
| `healthcheck needs the metrics/health server` | `METRICS_ENABLED=false` or `METRICS_ADDR` empty — re-enable it or disable the container healthcheck |
| `connection refused` | The HTTP server could not bind `METRICS_ADDR` (check logs for `metrics server error`) |
| `storage: open /data/state.db: timeout` | You are running an image older than this fix; the old healthcheck opened the locked database. Upgrade. |

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

**5. Ask the bouncer for its health status:**

```bash
docker exec abuseipdb-bouncer /usr/local/bin/bouncer healthcheck
echo "Healthcheck exit code: $?"
```

The JSON output shows the last successful LAPI pull, the last good AbuseIPDB call, and the consecutive AbuseIPDB failure count.

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
