# Design Rationale

Architecture decisions and design philosophy for the CrowdSec AbuseIPDB Bouncer.

## Table of Contents

- [Language Choice](#language-choice)
- [Process Model](#process-model)
- [Security Architecture](#security-architecture)
- [Decision Filter Pipeline](#decision-filter-pipeline)
- [Sink Interface](#sink-interface)
- [State Management](#state-management)
- [Retry Logic](#retry-logic)
- [Testing Strategy](#testing-strategy)

---

## Language Choice

**Go** was chosen over Python and shell for the following reasons:

**Single static binary.** `CGO_ENABLED=0` produces a fully static binary with no dynamic library dependencies. This enables the use of a distroless base image with no shell, no package manager, and no OS utilities -- reducing the attack surface to essentially zero beyond the binary itself and the CA certificate bundle.

**Type safety.** The filter pipeline, scenario mapper, and state management all benefit from compile-time type checking. The original shell implementation parsed untyped JSON strings at runtime; the Go implementation uses typed structs from the first byte read off the wire.

**Testability.** Every component is covered by unit tests. The shell implementation had no automated tests and could only be verified end-to-end against a live CrowdSec instance.

**Native LAPI integration.** CrowdSec maintains an official Go bouncer library (`go-cs-bouncer`) that handles authentication, long-polling, decision streaming, and reconnection. Using it eliminates the indirection of the previous architecture (custom-bouncer binary → stdin pipe → shell script → curl).

**Binary size.** The compiled binary is approximately 8MB. With the distroless base, the total image is 10-15MB -- comparable to the previous Alpine-based image but with a dramatically smaller attack surface.

---

## Process Model

The previous implementation used three layers:

```
custom-bouncer binary  (polls LAPI, deduplicates, spawns script)
       |
       | JSON via stdin
       v
reporter.sh            (filters, maps categories, enforces state)
       |
       | curl subprocess
       v
AbuseIPDB API
```

The current implementation uses one:

```
cs-abuseipdb-bouncer   (polls LAPI, filters, maps, enforces state, reports)
       |
       | net/http (TLS 1.2+)
       v
AbuseIPDB API
```

Removing two layers eliminates:
- Subprocess spawning overhead (each curl call was a new process)
- JSON parsing via jq (a runtime dependency)
- Stdin buffering and partial-read edge cases
- Script restart logic managed by the bouncer binary
- Config template rendering via sed in the entrypoint script

---

## Security Architecture

### Distroless Base Image

The runtime image is `gcr.io/distroless/static-debian12:nonroot`. It contains:
- The Go binary
- CA certificates (for outbound TLS)
- Timezone data (for UTC midnight quota resets)
- Nothing else

There is no shell (`/bin/sh`), no package manager, no coreutils, no `curl`, no `wget`. An attacker who achieves code execution inside the container has no tools to work with.

### Least Privilege

```yaml
# docker-compose.yml
read_only: true          # Root filesystem is read-only
cap_drop: [ALL]          # No Linux capabilities
security_opt:
  - no-new-privileges    # Cannot gain privileges via setuid
```

The container runs as UID 65532 (the distroless nonroot user). It writes only to `/tmp/cs-abuseipdb`, which is mounted as a named volume or tmpfs.

### Secret Handling

API keys are loaded exclusively from environment variables. They are never written to disk, never appear in log output, and are not baked into the image. The `.env` file (which contains the keys) is listed in `.gitignore`.

### TLS Policy

All outbound connections enforce TLS 1.2 as the minimum version:

```go
transport := &http.Transport{
    TLSClientConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
    },
}
```

This is set unconditionally in the AbuseIPDB client. For LAPI connections, the `go-cs-bouncer` library uses the standard Go TLS defaults, which also enforce TLS 1.2+ on Go 1.18 and later.

---

## Decision Filter Pipeline

Decisions pass through nine ordered filters before reaching any sink. The first filter to reject a decision terminates the pipeline (short-circuit evaluation).

```
Decision from LAPI
       |
       v
1. ActionFilter("add")          -- reject deletes
       |
       v
2. ScenarioExclude(             -- reject account heuristics
     "impossible-travel",
     "impossible_travel")
       |
       v
3. OriginAllow(                 -- reject CAPI/lists
     "crowdsec", "cscli")
       |
       v
4. ScopeAllow("ip")             -- reject ranges/ASNs/countries
       |
       v
5. ValueRequired()              -- reject empty value field
       |
       v
6. PrivateIPReject()            -- reject RFC1918, loopback, CGNAT, etc.
       |
       v
7. MinDurationFilter(cfg)       -- reject short bans (optional)
       |
       v
8. QuotaFilter(quota)           -- reject when daily limit reached
       |
       v
9. CooldownFilter(cooldown)     -- reject within 15-min window
       |
       v
   AbuseIPDB sink
```

Each filter is a typed function: `func(d *Decision) *SkipReason`. Returning `nil` passes; returning a `*SkipReason` rejects with a named reason for logging.

This pipeline is tested exhaustively in `internal/decision/filter_test.go` and `internal/bouncer/bouncer_test.go`.

### Impossible-Travel Exclusion

Impossible-travel scenarios detect account compromise by correlating authentication events from geographically distant locations. The source IP in these decisions is the legitimate user's current location -- not an attacker. Reporting it to AbuseIPDB would flag innocent IPs.

### CAPI/Lists Exclusion

Community blocklist (CAPI) IPs are already globally aggregated by CrowdSec. Re-reporting them to AbuseIPDB is redundant and wastes daily quota. Only locally-detected decisions (`crowdsec` origin from scenario matching) and manual decisions (`cscli` origin) are eligible.

### Private IP Exclusion

Private and reserved IP ranges are rejected by `internal/decision/ip.go` using `net/netip`, which is exact and immune to regex edge cases:

```
10.0.0.0/8      RFC 1918 private
172.16.0.0/12   RFC 1918 private
192.168.0.0/16  RFC 1918 private
127.0.0.0/8     Loopback (RFC 5735)
169.254.0.0/16  Link-local (RFC 3927)
0.0.0.0/8       This network (RFC 1122)
100.64.0.0/10   CGNAT (RFC 6598)
::1/128         IPv6 loopback (RFC 4291)
fe80::/10       IPv6 link-local (RFC 4291)
fc00::/7        IPv6 unique local (RFC 4193)
```

---

## Sink Interface

```go
type Sink interface {
    Name() string
    Report(ctx context.Context, r *Report) error
    Healthy(ctx context.Context) error
    Close() error
}
```

AbuseIPDB is the first and only implementation. The interface exists to support future reporters (Slack alerts, webhook POST, MISP feed, custom SIEM) without modifying the bouncer's event loop.

Sinks own their own category mapping. The `Report` struct carries only `IP`, `DecisionID`, `Scenario`, and `Duration` -- the AbuseIPDB sink translates `Scenario` to category IDs internally. A hypothetical Slack sink would format a different message from the same input.

---

## State Management

State is stored as plain files in a configurable directory (default `/tmp/cs-abuseipdb`). This matches the previous implementation's format for backward compatibility.

### Daily Quota Counter

File: `daily`
Format: `"<count> <YYYY-MM-DD>"` (e.g., `"42 2026-02-17"`)

The date is checked on every quota operation. If the stored date differs from the current UTC date, the counter is reset to zero. Writes are atomic (write to `.tmp`, then `os.Rename`), preventing corruption from interrupted writes.

### Per-IP Cooldown

Directory: `cooldown/`
Files: one per IP (e.g., `203_0_113_42`)
Format: Unix timestamp of expiry (e.g., `"1739840130"`)

IPv6 colons are replaced with underscores to avoid nested directory creation. CIDR suffixes are stripped before filename generation.

The `Allow()` method reads the file and compares the expiry timestamp to the current time. A missing file means no cooldown. A corrupt file (unparseable timestamp) is treated as no cooldown and will be overwritten on the next `Record()` call.

`Prune()` scans the directory and deletes files whose expiry has passed. It is called every 200 processed decisions and on graceful shutdown.

---

## Retry Logic

The AbuseIPDB client uses a custom retry strategy rather than a generic retry library. The semantics are too specific for a general-purpose implementation:

```
Attempt 1
  |
  +-- Success (200) ---------> done
  +-- Duplicate (422) -------> done (not an error)
  +-- Rate limited (429) ----> sleep Retry-After, return error (no retry)
  +-- Unauthorized (401) ----> return error (no retry)
  +-- Network error ---------> wait 5s, retry
  +-- Unexpected (5xx) ------> wait 5s, retry
  |
Attempt 2 (if retrying)
  |
  +-- Same as above
  +-- Network error ---------> wait 10s, retry
  |
Attempt 3 (if retrying)
  |
  +-- Failure ---------------> return error
```

Key decisions:
- 401 never retries. A bad API key will not improve with time.
- 422 is silently accepted. A duplicate report within 15 minutes is expected and normal.
- 429 reads the `Retry-After` value from the response body (not the header) and sleeps, then returns an error. The decision is not retried because quota is already exhausted.
- Network errors and 5xx responses retry with a doubling backoff: 5s after attempt 1, 10s after attempt 2.

---

## Testing Strategy

All packages have `_test.go` files with table-driven tests. External dependencies are mocked:

- **AbuseIPDB API:** `httptest.NewServer` in `client_test.go` -- no real API calls in tests
- **CrowdSec LAPI:** The `StreamBouncer` is not used in unit tests. `bouncer_test.go` calls `processDecision` directly with typed arguments
- **Filesystem:** `t.TempDir()` provides isolated, automatically-cleaned directories for state tests

```bash
# Run all tests
go test ./...

# Race detector (recommended before any pull request)
go test -race ./...

# Coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```
