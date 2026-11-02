# CrowdSec Remediation Component Compliance

Technical compliance checklist for `cs-abuseipdb-bouncer` as an outbound reporting sink.

## Scope & Applicability

This component consumes CrowdSec LAPI decisions and reports qualifying malicious IP decisions to AbuseIPDB. It is not an inline traffic remediation gateway.

Intentionally out of scope for this repository:
- AppSec forwarding / inline request inspection
- CAPTCHA and remediation HTML pages
- Reverse proxy, firewall rule programming, or packet filtering

## Compliance Matrix

| Specification Anchor | Required Behavior | Implementation in This Repo | Status | Evidence |
|---|---|---|---|---|
| User-Agent | Identify bouncer requests with stable UA string | LAPI client UA is built as `cs-abuseipdb-bouncer/<VERSION>` | Implemented | `internal/bouncer/bouncer.go` (`lapiUserAgent`, stream config) |
| Stream Mode | Poll LAPI decisions stream with startup bootstrap + periodic fetch | Uses `github.com/crowdsecurity/go-cs-bouncer` `StreamBouncer` and `GET /v1/decisions/stream` with startup phase | Implemented | `internal/bouncer/bouncer.go`, `go.mod` (`go-cs-bouncer`) |
| Default Poll Frequency | Stream update frequency default is 10s | `POLL_INTERVAL` default is `2s`; minimum enforced `2s`. This is a deliberate deviation from the specification's `10s` default; set `POLL_INTERVAL=10s` to match the specification (the bundled `docker-compose.yml` sets `30s`) | Deviation (deliberate) | `internal/config/config.go` defaults + validation |
| LAPI Telemetry | Push remediation usage metrics to LAPI | Background sender pushes to `POST /v1/usage-metrics` on interval | Implemented | `internal/bouncer/bouncer.go` (sender start + POST path), `internal/telemetry/sender.go` |
| Auth Modes | Support API key OR mTLS cert/key auth to LAPI | API-key and mTLS fields are wired; config validation enforces mutually exclusive auth mode and cert/key pairing | Implemented | `internal/config/config.go` (validation), `internal/bouncer/bouncer.go` (StreamBouncer `APIKey`/`CertPath`/`KeyPath`/`CAPath`) |
| Graceful Cleanup | Dispose resources on SIGTERM/SIGINT | Root command uses signal-aware context; bouncer drains workers and closes HTTP/store/sinks on shutdown | Implemented | `cmd/bouncer/main.go`, `internal/bouncer/bouncer.go` (`Run`, `Close`) |

## Telemetry Payload Structure

Telemetry payloads are built by `internal/telemetry/payload.go` and pushed by `internal/telemetry/sender.go`.

High-level structure:
- Top-level `remediation_components[]`
- Component metadata:
  - `type` = `cs-abuseipdb-bouncer`
  - `version`
  - `os` (`name`, `version`)
  - `feature_flags` (empty array)
  - `utc_startup_timestamp`
- `metrics[]` array; each entry contains:
  - `items[]` with the `processed` metric (`unit=request`, value = successful AbuseIPDB reports in window)
  - `meta` (`window_size_seconds`, `utc_now_timestamp`)

Security characteristics:
- Aggregated counters only
- No request payload capture
- No credentials in telemetry body
- API keys/Bearer tokens are redacted from logs elsewhere in runtime

## Operational Verification Checklist

1. Verify defaults and auth mode:
```bash
docker logs -f abuseipdb-bouncer
```
Check the `bouncer started` line for the expected limit, cooldown and worker settings, and the `usage-metrics sender started` line for the telemetry interval. `POLL_INTERVAL` is not logged; it defaults to `2s` (`30s` in the bundled `docker-compose.yml`).

2. Verify stream polling and bouncer registration:
```bash
docker exec crowdsec cscli bouncers list
```
Confirm `last_pull` updates.

3. Verify decision ingestion to reporting path:
```bash
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "compliance test"
docker logs -f abuseipdb-bouncer
```
Expect `reporting` and `reported` log lines for the IP. The `decision received` line is logged at debug level only, so it appears only with `LOG_LEVEL=debug`.

4. Verify telemetry worker is active:
```bash
docker logs abuseipdb-bouncer 2>&1 | grep 'usage-metrics sender started'
docker logs abuseipdb-bouncer 2>&1 | grep 'usage metrics push failed'
```
Expect the sender startup line. Every `USAGE_METRICS_INTERVAL` (default `30m`) the sender pushes the window's count; a window with no successful reports pushes nothing. Successful pushes are not logged. A failed push logs `usage metrics push failed` at warn level and keeps the count for the next interval, so the second command should print nothing.

5. Verify metrics endpoint (local observability):
```bash
curl -s http://127.0.0.1:9090/metrics | grep cs_abuseipdb
```
Confirm decision/report counters are exposed.

## Implementation Reference Index

- Stream setup, UA, mTLS wiring, telemetry push loop: `internal/bouncer/bouncer.go`
- Auth and interval validation defaults: `internal/config/config.go`
- Build version propagation + signal lifecycle: `cmd/bouncer/main.go`
- Telemetry payload/counter/sender internals: `internal/telemetry/payload.go`, `internal/telemetry/counter.go`, `internal/telemetry/sender.go`
