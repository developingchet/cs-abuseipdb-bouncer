# AGENTS.md

## Project

A CrowdSec bouncer that reads new decisions from the CrowdSec LAPI stream and reports them to AbuseIPDB. Its filters (README "Filtered Decisions") do not check the decision type, so ban, captcha and other types are all reported. It is a single Go binary (`cmd/bouncer`), released as a distroless multi-arch Docker image and as binaries for linux/amd64, linux/arm64 and windows/amd64. The README's "How It Works" diagram shows the data flow, its "Repository Structure" table describes every directory, and `docs/DESIGN.md` explains the design decisions.

| Path | Contents |
|---|---|
| `cmd/bouncer/` | Cobra CLI: `run` (default), `version`, `healthcheck` |
| `internal/bouncer/` | Run loop, worker pool, retry worker, janitor, health endpoints; assembles the filter pipeline |
| `internal/decision/` | Filter implementations and the private/reserved range list |
| `internal/sink/` | `Sink` interface and typed errors (duplicate, whitelisted, rate limit, permanent, unauthorized) |
| `internal/sink/abuseipdb/` | AbuseIPDB client and the scenario-to-category mapping (`mapper.go`) |
| `internal/storage/` | bbolt state (quota, cooldowns, retry queue) and an in-memory store for tests |
| `internal/config/` | Environment and YAML configuration with validation |
| `internal/logger/` | Logrus bridge and API key redaction (`redact.go`) |
| `internal/metrics/`, `internal/telemetry/` | Prometheus metrics and the LAPI usage-metrics push |
| `security/seccomp-bouncer.json` | Seccomp allowlist used by `docker-compose.yml` |

## Setup and checks

Go 1.27.4 or later (the version in `go.mod`). The tests mock CrowdSec and AbuseIPDB and need no network access.

```bash
go mod download
gofmt -l cmd internal                      # must print nothing; CI does not run gofmt
go test ./... -count=1                     # unit tests
go test -race ./... -count=1 -timeout=120s # CI's test command; -race needs CGO and a C compiler
bash scripts/test-coverage.sh              # CI gate: every package at 100% statement coverage
go vet ./...
golangci-lint run ./...                    # golangci-lint v2 (CI pins it in ci.yml), built with Go 1.27.4 or later
go mod verify
go run -modfile=.github/tools/go.mod golang.org/x/vuln/cmd/govulncheck ./...
bash scripts/validate-seccomp.sh ./security/seccomp-bouncer.json  # needs jq
go build -o bin/bouncer ./cmd/bouncer
docker compose build                       # local image build from the Dockerfile
```

The `Makefile` wraps most of these (`make test`, `make coverage-check`, `make ci-test`, `make lint`). CI also runs the built image under the seccomp profile.

## Conventions

- Format with `gofmt`. Return wrapped errors instead of panicking, and log through zerolog with structured fields, never values formatted into the message.
- New code keeps every package at 100% statement coverage; table-driven tests and `t.TempDir()` are the norm.
- A new `go.mod` dependency needs an issue discussing it first.
- Scenario mappings in `internal/sink/abuseipdb/mapper.go` are first-match substring rules: put specific patterns before generic ones and add a case to `mapper_test.go`.
- Keep the runtime image distroless with no added tools, and keep `read_only`, `cap_drop: [ALL]` and `no-new-privileges` in `docker-compose.yml`.
- A syscall the binary newly needs must be added to `security/seccomp-bouncer.json` and to the required list in `scripts/validate-seccomp.sh`.
- A new setting is passed explicitly by `docker-compose.yml`, so add it there and to `.env.example`, `docs/CONFIGURATION.md`, the README Configuration Summary and `DOCKERHUB.md`.
- Commit subjects follow Conventional Commits (`feat:`, `fix:`, `docs:`, `ci:`, `chore:`).

## Security and data

- Each report sends AbuseIPDB the IP address, its categories and the comment `CrowdSec detection | scenario: <scenario>`, authenticated with the account's API key. For manual `cscli` decisions the scenario is the operator's reason, or `manual '<type>' from '<machine login>'` when none is given. A change to the payload must update the README's "Data Sent to AbuseIPDB" section in the same pull request.
- New tests and examples use documentation addresses (`203.0.113.0/24`, `198.51.100.0/24`, `2001:db8::/32`). Automated tests never call the real AbuseIPDB API; live reports happen only in the manual tests documented in `CONTRIBUTING.md`, `docs/SETUP.md`, `docs/TROUBLESHOOTING.md` and `COMPLIANCE.md`, which use `203.0.113.42` because documentation ranges are not filtered.
- Never commit API keys, `.env` files or logs with real addresses. API keys must stay covered by the redaction in `internal/logger/redact.go`; add a test there when a new secret format appears in output.
- Vulnerabilities are reported privately as described in `SECURITY.md`, not in issues or pull requests.

## Pull requests

Fill in `.github/PULL_REQUEST_TEMPLATE.md`: list the checks run and those skipped, and note any change to the reported data, settings or upgrade behaviour. Behaviour changes get an upgrade note in the README.
