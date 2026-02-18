# Design Rationale

Architecture decisions and design philosophy for the CrowdSec AbuseIPDB Bouncer.

## Table of Contents

- [Language Choice](#language-choice)
- [Process Model](#process-model)
- [Security Architecture](#security-architecture)
- [Decision Filter Pipeline](#decision-filter-pipeline)
- [Concurrent Worker Pool](#concurrent-worker-pool)
- [Sink Interface](#sink-interface)
- [State Management](#state-management)
- [Retry Logic](#retry-logic)
- [Supply-Chain Security](#supply-chain-security)
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
  - "seccomp:./security/seccomp-bouncer.json"
```

The container runs as UID 65532 (the distroless nonroot user). It writes only to `/data` (named volume, bbolt database) and `/tmp` (tmpfs mount for the Go runtime).

### Seccomp Profile

`security/seccomp-bouncer.json` is a minimal OCI seccomp profile with `defaultAction: SCMP_ACT_ERRNO`. It permits only the syscalls the bouncer actually uses, grouped by function:

- **File I/O:** `read`, `write`, `open`, `openat`, `close`, `stat`, `fstat`, `lstat`, `fstatfs`, `lseek`, `fsync`, `fdatasync`, `ftruncate`, `rename`, `unlink`, `mkdir`, `access`, `faccessat`, `newfstatat`, `getcwd`, `openat2`
- **Memory:** `mmap`, `mprotect`, `munmap`, `mremap`, `madvise`, `brk`
- **Network (TCP):** `socket`, `connect`, `bind`, `listen`, `accept`, `accept4`, `getsockname`, `getpeername`, `setsockopt`, `getsockopt`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `shutdown`
- **I/O multiplexing:** `poll`, `epoll_create1`, `epoll_ctl`, `epoll_pwait`, `select`, `pselect6`, `pipe2`, `eventfd2`
- **Threading/sync:** `clone3`, `futex`, `set_robust_list`, `get_robust_list`, `sched_yield`, `tgkill`, `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`
- **Clock/time:** `clock_gettime`, `clock_getres`, `nanosleep`, `clock_nanosleep`, `gettimeofday`
- **Process:** `exit_group`, `getpid`, `gettid`, `dup2`, `dup3`, `getrandom`, `arch_prctl`

### Secret Handling

API keys are loaded exclusively from environment variables. They are never written to disk and are not baked into the image. A `RedactWriter` (`internal/logger/redact.go`) wraps stderr and applies two regular expressions before any log line reaches the output:

1. `[A-Fa-f0-9]{80}` → `[REDACTED-API-KEY]` — matches the 80-character hex format used by both AbuseIPDB and CrowdSec API keys
2. `(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*` → `bearer [REDACTED]` — matches Bearer tokens in any case

The writer always returns `len(p)` (the original byte count) to satisfy zerolog's internal accounting even when the redacted output is shorter.

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

Decisions pass through two ordered pipelines:

### Pre-Queue Pipeline (main event loop — stateless, no I/O)

Seven filters run synchronously in the event loop before a decision is enqueued for the worker pool. Because these filters perform no I/O, they cannot block the loop.

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
   [enqueue to worker pool — non-blocking, drops on overflow]
```

### Worker-Side Checks (atomic bbolt transactions)

Each worker dequeues a job and runs two atomic store operations before calling any sink:

```
Worker receives job
       |
       v
8. CooldownConsume(ip)          -- single bolt.Update:
                                   read expiry, check, set, commit
       |  false → skip (no quota consumed)
       v
9. QuotaConsume()               -- single bolt.Update:
                                   read count, check, increment, commit
       |  false → skip
       v
   AbuseIPDB sink
```

The order (cooldown before quota) is intentional: a cooldown hit does not consume a quota unit.

### Why Two Pipelines?

The original single synchronous pipeline (all 9 filters in the event loop) blocked the event loop for the duration of every AbuseIPDB HTTP round-trip (up to ~15 s with retries during rate-limiting). During a high-frequency ban wave, decisions could back up in the LAPI stream while the bouncer waited for one HTTP call to complete.

The two-pipeline design separates the fast stateless checks (nanoseconds, run in the loop) from the slow I/O-bound operations (milliseconds to seconds, run in parallel workers). The quota and cooldown checks were moved to the worker side because they require write access to the bbolt database -- a serialisation point anyway -- and are tightly coupled to the decision whether to actually call AbuseIPDB.

Each filter is a typed function: `func(d *Decision) *SkipReason`. Returning `nil` passes; returning a `*SkipReason` rejects with a named reason for logging and metrics.

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

## Concurrent Worker Pool

### Design

`internal/bouncer/pool.go` implements a fixed-size goroutine pool backed by a buffered channel:

```go
type workerPool struct {
    jobCh chan workerJob   // bounded channel (WORKER_BUFFER capacity)
    wg    sync.WaitGroup  // tracks live workers
    store storage.Store
    sinks []sink.Sink
}
```

**Submission** is non-blocking. If the channel is full, the job is dropped and `DecisionsSkipped.WithLabelValues("buffer-full")` is incremented. This prevents the event loop from ever blocking on the pool, at the cost of dropping decisions during traffic spikes. The buffer size (`WORKER_BUFFER`, default 256) should be set to match the expected burst depth.

**Shutdown** is cooperative: `pool.stop()` closes `jobCh`, which causes workers to drain remaining buffered jobs (if the context is still live) and then exit. `wg.Wait()` ensures all workers have fully exited before the function returns. This is called both on context cancellation and on LAPI stream close.

### Known Limit: bbolt Write Serialisation

bbolt serialises all write transactions — only one `db.Update` runs at a time. Under very high concurrency this means `CooldownConsume` and `QuotaConsume` calls from different workers queue behind each other. In practice, the AbuseIPDB HTTP round-trip (100 ms–15 s) dominates worker latency by orders of magnitude, so bbolt is never the bottleneck at realistic worker counts (default 4, max 64).

If bbolt serialisation does become a bottleneck at very high scale, the recommended path is to replace `BoltStore` with a Redis-backed implementation of the `Store` interface — the interface boundary (`QuotaConsume`, `CooldownConsume`) is already designed for atomic operations.

### Response Buffer Pooling

`internal/sink/abuseipdb/client.go` uses a `sync.Pool` of `*bytes.Buffer` to reuse response body read buffers across concurrent requests:

```go
var respBufPool = sync.Pool{
    New: func() any { return bytes.NewBuffer(make([]byte, 0, 4096)) },
}
```

Each use copies the buffer contents to a fresh `[]byte` before returning the buffer to the pool. This prevents use-after-pool-put bugs while still avoiding per-request heap allocations for the common case where responses fit within 4096 bytes.

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

State is stored in a single `state.db` file using [bbolt](https://github.com/etcd-io/bbolt), an embedded ACID key-value store. The database contains two buckets.

### Daily Quota Counter (`quota` bucket)

**Key:** `today` (constant)
**Value:** JSON-encoded struct

```json
{"count": 42, "date": "2026-02-17"}
```

The date is checked inside every `QuotaConsume` transaction. If the stored date differs from the current UTC date, the counter is reset to zero before the check proceeds. The entire read-check-increment sequence runs in a single `bolt.Update` (serialised write transaction), making the operation atomic and race-free even with multiple concurrent workers.

### Per-IP Cooldown (`cooldown` bucket)

**Key:** sanitised IP string (e.g. `203_0_113_42` for IPv4, `2001_db8__1` for IPv6 — colons and dots replaced with underscores)
**Value:** big-endian int64 Unix timestamp of expiry (8 bytes)

`CooldownConsume(ip)` runs in a single `bolt.Update`:
1. Read the stored expiry for `ip`
2. If the current time is before expiry, return `(false, nil)` — cooldown active, do not report
3. Otherwise, write the new expiry (`now + cooldownDuration`) and return `(true, nil)`

This atomic check-and-set eliminates the TOCTOU race present in the earlier separate `CooldownAllow()` + `CooldownRecord()` design, where two concurrent workers could both observe "no cooldown" and both proceed to report the same IP.

### Cooldown Pruning (Janitor)

`internal/bouncer/janitor.go` runs a background goroutine on a configurable tick (`JANITOR_INTERVAL`, default 5 minutes):

1. **Prune:** `store.CooldownPrune()` deletes all cooldown entries whose expiry timestamp is in the past. This bounds the growth of `state.db` to the number of unique IPs seen within the cooldown window.
2. **DB size metric:** `os.Stat(store.DBPath()).Size()` is written to the `cs_abuseipdb_bbolt_db_size_bytes` Prometheus gauge. This metric is useful for detecting unexpected growth (e.g. a misconfigured cooldown of 0 seconds generating millions of entries).

The janitor exits cleanly when its context is cancelled (the same context as the bouncer's `Run` loop).

### Why bbolt?

- **No external dependencies** — the database is embedded in the binary; no Redis, no PostgreSQL, no external process to manage
- **ACID guarantees** — crash-consistent; a power failure mid-write does not corrupt the database
- **Single file** — trivial to back up, inspect, or copy (`cp state.db state.db.bak`)
- **Sufficient performance** — bbolt serialises write transactions, but the AbuseIPDB HTTP call dominates latency by orders of magnitude; bbolt is never the bottleneck

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

## Supply-Chain Security

### Cosign (Keyless OIDC Signing)

Every release tag triggers a GitHub Actions workflow that signs the published Docker image using [Cosign](https://docs.sigstore.dev/cosign/overview/) in keyless mode. The signature is issued against the GitHub Actions OIDC token — no private key is stored anywhere.

```yaml
permissions:
  id-token: write  # required for OIDC token issuance
```

Verification:

```bash
cosign verify developingchet/cs-abuseipdb-bouncer:<tag> \
  --certificate-identity-regexp="https://github.com/developingchet/cs-abuseipdb-bouncer/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

### CycloneDX SBOM

The `anchore/sbom-action` step generates a CycloneDX JSON SBOM from the published image after it is pushed to Docker Hub. The SBOM is:

1. Attached to the GitHub Release as `cs-abuseipdb-bouncer.sbom.cyclonedx.json`
2. Embedded as a Cosign attestation on the Docker image (`cosign attest --type cyclonedx`)

The SBOM lists every package present in the image, enabling downstream consumers to check for known CVEs in the exact packages shipped.

### Trivy Scan

Every release pipeline runs `aquasecurity/trivy-action` against the built image before pushing to Docker Hub. The step fails (and blocks publication) if any HIGH or CRITICAL CVEs are found in packages with available fixes.

---

## Testing Strategy

All packages have `_test.go` files with table-driven tests. External dependencies are mocked:

- **AbuseIPDB API:** `httptest.NewServer` in `client_test.go` -- no real API calls in tests
- **CrowdSec LAPI:** The `StreamBouncer` is not used in unit tests. `bouncer_test.go` calls `processDecision` directly with typed arguments
- **Filesystem:** `t.TempDir()` provides isolated, automatically-cleaned directories for bbolt tests

### Concurrency Tests

`internal/storage/bbolt_concurrent_test.go` verifies the atomic store operations under real concurrent load:

| Test | Scenario | Invariant |
|------|----------|-----------|
| `TestQuotaConsume_Concurrent` | 50 goroutines, limit=10 | Exactly 10 succeed |
| `TestCooldownConsume_SameIP` | 20 goroutines, 1 IP | Exactly 1 succeeds |
| `TestCooldownConsume_DifferentIPs` | 20 goroutines, 20 IPs | All 20 succeed |

All tests are run with `-race` in CI.

### Worker Pool Tests

`internal/bouncer/pool_test.go` covers the end-to-end pool behaviour using an in-memory store and stub sinks:

| Test | What it validates |
|------|-------------------|
| `TestWorkerPool_10kDecisions` | 10k decisions, 8 workers — no panic, deadlock, or race |
| `TestWorkerPool_QuotaNotExceeded` | 100 decisions, limit=10 — sink receives ≤ 10 reports |
| `TestWorkerPool_CooldownAtomicity` | 200 decisions for 1 IP — sink receives exactly 1 report |
| `TestWorkerPool_Backpressure` | Buffer=10, flood 3× — drops observed, no deadlock |
| `TestWorkerPool_GracefulShutdown` | Cancel mid-flight — `stop()` returns within 5s |

```bash
# Run all tests with race detector
go test -race ./... -count=1 -timeout=120s

# Targeted concurrency tests
go test -race -count=5 ./internal/storage/... -run TestCooldownConsume_SameIP
go test -race -count=5 ./internal/bouncer/... -run TestWorkerPool_CooldownAtomicity

# Coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```
