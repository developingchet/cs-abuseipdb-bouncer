# Design Rationale

Architecture decisions and design philosophy for the CrowdSec AbuseIPDB Bouncer.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Technology Choices](#technology-choices)
- [Security Considerations](#security-considerations)
- [Reliability Patterns](#reliability-patterns)
- [Performance Optimization](#performance-optimization)
- [Trade-offs and Limitations](#trade-offs-and-limitations)

## Architecture Overview

### Component Interaction

```
┌──────────────────┐
│   CrowdSec LAPI  │ (Port 8080/8443)
└────────┬─────────┘
         │
         │ HTTPS polling (every 30s)
         │ Returns JSON decisions stream
         │
         v
┌──────────────────────────┐
│ crowdsec-custom-bouncer  │ (Official Docker image)
│  - Polls LAPI            │
│  - Caches decisions      │
│  - Spawns subprocess     │
└──────────┬───────────────┘
           │
           │ stdin pipe (JSON, one per line)
           │ {"action":"add","origin":"crowdsec",...}
           │
           v
┌────────────────────────────────┐
│ crowdsec-abuseipdb-reporter.sh │ (POSIX ash script)
│   1. Parse JSON                │
│   2. Skip if action != "add"   │
│   3. Skip impossible-travel    │
│   4. Check origin whitelist    │
│   5. Skip if scope != "Ip"     │
│   6. Skip if value is empty    │
│   7. Skip private IP ranges    │
│   8. Check min_duration filter │
│   9. Check daily budget        │
│  10. Check per-IP cooldown     │
│  11. Optional: /check precheck │
│  12. Map scenario→categories   │
│  13. POST to AbuseIPDB         │
│  14. Update state files        │
└────────────┬───────────────────┘
             │
             │ HTTPS POST
             │ categories, comment
             │
             v
┌──────────────────────┐
│ AbuseIPDB v2 API     │
│  /report endpoint    │
└──────────────────────┘
```

### Data Flow

1. **Polling Phase**: Every 30 seconds, the bouncer queries `/v1/decisions/stream` with a cursor
2. **Caching Phase**: Bouncer caches decisions for 15 minutes to prevent duplicate invocations
3. **Streaming Phase**: New decisions are written to the reporter's stdin as JSON, one per line
4. **Processing Phase**: Reporter parses, filters, and validates each decision
5. **State Check Phase**: Reporter checks per-IP cooldown and daily quota
6. **Reporting Phase**: Eligible IPs are POSTed to AbuseIPDB with mapped categories
7. **State Update Phase**: Reporter updates cooldown timestamp and daily counter

### State Management

State is stored in `/tmp/cs-abuseipdb` (Docker volume mount).

**Directory structure:**

```
/tmp/cs-abuseipdb/
├── daily                          # "count YYYY-MM-DD"
└── cooldown/
    ├── 203_0_113_42               # IP cooldown timestamp
    ├── 198_51_100_1
    └── ...
```

**Cooldown files:**
- Filename: IP address with `.:/+` replaced by `_` (safe for filesystems)
- Content: Unix timestamp (seconds since epoch)
- Lifespan: Auto-pruned after 15 minutes to prevent unbounded growth

**Daily counter:**
- Format: `count date` (e.g., "42 2026-02-16")
- Reset logic: If file date != today's date, reset count to 0
- Atomic: Single file read/write per report

## Technology Choices

### Custom Bouncer Over Alternatives

**Decision:** Use `crowdsecurity/custom-bouncer` as the integration framework.

**Alternatives considered:**
1. Cron job polling LAPI directly
2. CrowdSec notification plugin
3. Standalone Python/Go service

**Rationale:**
- **Official support**: Maintained by CrowdSec team, follows LAPI best practices
- **Built-in features**: Automatic polling, cursor management, decision caching, retry logic
- **Low maintenance**: No need to implement LAPI streaming protocol ourselves
- **Proven**: Used by other community bouncers (firewall, cloudflare, etc.)

**Trade-offs:**
- Adds one extra process layer (bouncer → script vs. direct integration)
- Limited control over polling frequency (minimum 10s)
- Requires understanding of both bouncer config and script behavior

### POSIX ash Over bash/Python/Go

**Decision:** Write the reporter in POSIX-compliant ash (BusyBox shell).

**Alternatives considered:**
1. Bash (richer features: arrays, `[[`, process substitution)
2. Python (easier JSON parsing, HTTP libraries)
3. Go (compile to single binary, type safety)

**Rationale:**
- **Size**: BusyBox ash is already in Alpine base image (no extra dependencies)
- **Performance**: Shell script has minimal overhead for I/O-bound work
- **Simplicity**: 400 lines of shell vs. 1000+ lines of Python with virtualenv setup
- **Transparency**: Users can read and modify the script without recompiling

**Trade-offs:**
- Shell scripting is error-prone (word splitting, exit code handling, quoting)
- JSON parsing requires `jq` (20MB dependency)
- No static type checking (errors found at runtime)

### State in Filesystem Over Database

**Decision:** Store state in flat files (one file per IP cooldown, one file for daily counter).

**Alternatives considered:**
1. SQLite database
2. Redis key-value store
3. In-memory only (no persistence)

**Rationale:**
- **Simplicity**: No database daemon, no schema migrations, no connection pooling
- **Atomic operations**: Filesystem writes are atomic for small files (<4KB)
- **Performance**: Comparable to SQLite for ~1000 files (typical active decision count)
- **Introspection**: Easy to debug (`ls`, `cat`) without special tools

**Trade-offs:**
- File count scales linearly with unique IPs (mitigated by auto-pruning)
- No transactions (cooldown and daily counter are separate files)
- Inode usage (one inode per file; volume must support many small files)

### Structured Logging

**Decision:** Emit logs in logrus format (`time="..." level=... msg="..."`).

**Rationale:**
- **Compatibility**: Matches CrowdSec's own log format (unified parsing)
- **Machine-readable**: Easy to parse with `jq`, `grep`, or log aggregators
- **Human-readable**: Still readable without tools (unlike pure JSON)

**Format:**
```
time="2026-02-16T20:15:30Z" level=info msg="reported ip=203.0.113.42 daily=15/1000"
```

Parseable with:
```bash
jq -R 'capture("time=\"(?<time>[^\"]+)\" level=(?<level>\\S+) msg=\"(?<msg>[^\"]+)\"")' 
```

## Security Considerations

### No PII in Reports

**Requirement:** Reports sent to AbuseIPDB must not contain personally identifiable information.

**Implementation:**
- Comment field contains only: `CrowdSec detection | scenario: <name>`
- No IP addresses, usernames, email addresses, hostnames, file paths, or log excerpts
- Scenario names are generic (e.g., "ssh-bf", "http-sqli-probing")

**Example report:**
```json
{
  "ip": "203.0.113.42",
  "categories": "22,18",
  "comment": "CrowdSec detection | scenario: ssh-bf"
}
```

**Rationale:**
- GDPR compliance (reporting IPs is permissible for security purposes, but logs may contain PII)
- AbuseIPDB policy forbids verbose logs in comments
- Comments are public on AbuseIPDB — any leaked PII is permanently visible

### API Key Security

**Requirements:**
- API keys must never appear in logs
- Keys must not be committed to git
- Container metadata should not expose keys

**Implementation:**
1. Keys are passed via environment variables (not CLI args)
2. Docker Compose reads from `.env` (which is gitignored)
3. Entrypoint script reads keys from env, never logs them
4. Reporter script uses keys from env, never prints them (even in debug mode)

**Verification:**
```bash
docker logs abuseipdb-bouncer | grep -i 'api.*key'  # Should return nothing
docker inspect abuseipdb-bouncer | grep -i 'api.*key'  # Should show only env var names, not values
```

### TLS Enforcement

**Requirement:** All API communication must use TLS 1.2 or higher.

**Implementation:**
- `curl --tlsv1.2` flag on all requests
- Rejects SSLv2, SSLv3, TLS 1.0, TLS 1.1 (vulnerable to POODLE, BEAST, etc.)

**LAPI connection:**
- Supports both HTTP (internal Docker network) and HTTPS (production)
- `insecure_skip_verify` option for self-signed certificates (user must explicitly enable)

### Principle of Least Privilege

**Container permissions:**
- Runs as non-root user (inherited from base image)
- No elevated capabilities
- No host network access
- No access to Docker socket
- Read-only volume mounts for scripts and config

**LAPI access:**
- Bouncer key grants read-only access to decisions endpoint
- Cannot add decisions, modify scenarios, or access hub/console features

## Reliability Patterns

### Dual-Layer Deduplication

**Problem:** Same IP may be reported twice due to race conditions or restarts.

**Solution:** Two independent deduplication layers:

1. **Bouncer-level cache** (15-minute TTL):
   - Prevents script invocation for duplicate decisions
   - Survives until bouncer restart
   - Based on decision type+value hash

2. **Script-level cooldown** (15-minute filesystem state):
   - Prevents API calls for recently-reported IPs
   - Survives bouncer restarts (persisted in volume)
   - Based on IP address only

**Result:** Even if the bouncer restarts mid-cooldown, the script will still reject the duplicate.

### Exponential Backoff on Transient Failures

**Problem:** Network errors and rate limits should not cause immediate failure.

**Solution:** Retry logic with exponential backoff:

```
Attempt 1: Immediate call
         ↓ (fails)
         Wait 5s
         ↓
Attempt 2: Retry
         ↓ (fails)
         Wait 10s
         ↓
Attempt 3: Retry
         ↓ (fails)
         Give up, log error
```

**Exceptions:**
- 401 Unauthorized: No retry (auth error is permanent)
- 422 Duplicate: No retry (duplicate is permanent)
- 429 Rate Limit: Honors `Retry-After` header, then gives up (no exponential backoff)

### Graceful Degradation

**Scenarios:**

1. **AbuseIPDB down**: Reports fail, but script continues processing. Daily counter is not incremented. Next batch of decisions will retry.

2. **LAPI down**: Bouncer retries connection with backoff. Script remains idle until connection restored.

3. **Daily quota exhausted**: Script logs warning and drops decisions. Continues processing (for logging), but skips API calls.

4. **Volume unmounted**: Startup validation fails with actionable error message. Container exits (healthcheck fails, restart loop triggers).

### Signal Handling

**SIGTERM/SIGINT:** Trap cleanup on exit.

```bash
trap _cleanup EXIT INT TERM

_cleanup() {
    find "$COOLDOWN_DIR" -maxdepth 1 -type f -mmin +15 -delete 2>/dev/null || true
}
```

Ensures stale cooldown files are pruned even on unclean shutdown.

## Performance Optimization

### Single jq Invocation Per Decision

**Anti-pattern:**
```bash
action=$(printf '%s' "$line" | jq -r '.action')
origin=$(printf '%s' "$line" | jq -r '.origin')
scenario=$(printf '%s' "$line" | jq -r '.scenario')
# ... 4 more jq calls per decision
```

**Optimized:**
```bash
parsed=$(printf '%s' "$line" | jq -r '
    (.action   // ""),
    (.origin   // ""),
    (.scenario // "unknown")
')
action=$(printf '%s' "$parsed" | sed -n '1p')
origin=$(printf '%s' "$parsed" | sed -n '2p')
```

**Benefit:** Reduces jq subprocess spawns from 7 to 1 per decision (~70% reduction in CPU time for JSON parsing).

### Lazy Evaluation

**Pattern:** Check cheap filters first, expensive operations last.

**Order:**
1. Action check (`[ "$action" = "add" ]`) — string comparison
2. Origin whitelist — loop over 2-item array
3. Scope check — case-insensitive string comparison
4. Private IP check — regex match
5. Cooldown check — file existence + timestamp comparison
6. **Then** make API call (most expensive)

### Cooldown File Pruning

**Problem:** Cooldown directory can accumulate thousands of files over time (one per unique IP).

**Solution:**
- Auto-prune every 200 decisions
- Delete files older than 15 minutes
- Happens in background (no impact on decision processing)

**Implementation:**
```bash
_prune_counter=$(( _prune_counter + 1 ))
[ "$(( _prune_counter % 200 ))" -eq 0 ] || return 0
find "$COOLDOWN_DIR" -maxdepth 1 -type f -mmin +15 -delete 2>/dev/null || true
```

## Trade-offs and Limitations

### No Sub-Second Precision

**Limitation:** Daily counter resets at UTC midnight, but the check is `date -u '+%Y-%m-%d'`, which has 1-second granularity.

**Impact:** Minimal. AbuseIPDB resets quota at midnight UTC with similar granularity.

**Alternative considered:** Store epoch seconds and compare. Rejected as unnecessarily complex for a daily boundary check.

### Last-Write-Wins for Concurrent Reports

**Scenario:** Two bouncer instances sharing the same state volume both try to report the same IP simultaneously.

**Behavior:**
1. Both read cooldown file (not present)
2. Both call AbuseIPDB API
3. First request succeeds (200)
4. Second request fails (422 duplicate)
5. Both write cooldown file (last write wins)

**Impact:** Wasted one API call. Rare in practice (would require decisions arriving within same 1-second window).

**Alternative considered:** File locking (flock). Rejected as overkill for infrequent occurrence.

### No Feedback Loop

**Limitation:** Reporter does not check if AbuseIPDB already has reports for an IP before reporting.

**Rationale:**
- Would require calling `/check` for every decision (doubles API usage)
- Check quota is separate but still limited (1000/day free tier)
- AbuseIPDB server-side deduplication handles duplicates (returns 422)

**Optional feature:** `ABUSEIPDB_PRECHECK=true` enables pre-checking for users who want this behavior.

### POSIX Compliance Constraints

**Limitation:** Ash lacks features present in bash:

- No `[[` test operator (use `[` with careful quoting)
- No arrays (use space-separated strings with word splitting)
- No process substitution `<(command)` (use temp files)
- No `local -r` (readonly locals)

**Impact:** Code is more verbose and requires careful attention to quoting and IFS handling.

**Benefit:** Script runs on any POSIX-compliant shell (dash, sh, ksh, zsh, bash).

### No Built-in Metrics

**Limitation:** Script does not expose Prometheus metrics for:
- Reports sent per scenario
- API error rates
- Cooldown hit rate

**Rationale:**
- Adding metrics requires either:
  1. Writing to files and serving them via HTTP (adds complexity)
  2. Using a push gateway (external dependency)
- The bouncer binary exposes basic metrics (script exits, decisions processed)
- Most users can extract metrics from structured logs (see CONFIGURATION.md)

**Future consideration:** Sidecar container that parses logs and exposes metrics.

## Design Evolution

### Why Not a Plugin for CrowdSec?

**Original consideration:** Implement as a CrowdSec notification plugin.

**Rejected because:**
- Notification plugins are triggered per-decision (no batching)
- No built-in cooldown/rate limit management
- Would duplicate LAPI polling logic
- Custom bouncer framework already exists and is well-suited

### Why Not Direct Database Access?

**Original consideration:** Query CrowdSec's SQLite database directly.

**Rejected because:**
- Bypasses LAPI (no RBAC, no audit trail)
- Direct DB access is not supported/documented
- Schema changes between CrowdSec versions could break integration
- LAPI is the official integration point

### Why File-Based State vs. Embedded Database?

**Reconsidered:** Use SQLite for state instead of flat files.

**Reaffirmed flat files because:**
- For 1000 active cooldowns, filesystem is comparable to SQLite in speed
- SQLite requires locking and journal files (complicates Docker volume story)
- Flat files are easier to debug and introspect
- Auto-pruning is simpler with `find` than with SQL DELETE + VACUUM

## Future Considerations

Potential enhancements for future versions:

1. **Multi-architecture Docker images** (ARM, ARM64) for Raspberry Pi deployments
2. **Kubernetes Helm chart** with configmap/secret management
3. **Metrics sidecar** for Prometheus integration
4. **Web UI** for viewing daily stats, recent reports, scenario distribution
5. **Webhook support** for notification on quota exhaustion or failures
6. **Custom category mapping** via external config file (avoid editing script)
