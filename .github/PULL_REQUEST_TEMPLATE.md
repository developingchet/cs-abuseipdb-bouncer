## Change

<!-- What changes and why. Link the issue it resolves, for example "Fixes #123". -->

## Checks run

<!-- Tick what you ran and passed. Leave a box unticked and say why if you skipped it. -->

- [ ] `gofmt -l cmd internal` prints nothing
- [ ] `go test -race ./... -count=1 -timeout=120s`
- [ ] `make coverage-check` (every package at 100% statement coverage)
- [ ] `go vet ./...` and `golangci-lint run ./...`
- [ ] `go mod verify` and `go run -modfile=.github/tools/go.mod golang.org/x/vuln/cmd/govulncheck ./...`
- [ ] For changes to the Dockerfile, `docker-compose.yml` or `security/seccomp-bouncer.json`: `bash scripts/validate-seccomp.sh ./security/seccomp-bouncer.json`, then `docker build -t cs-bouncer-test:ci .` and the `docker run` from the "Run container under seccomp profile" step of `.github/workflows/ci.yml` (no CrowdSec or real keys needed); its output must not contain `reopen exec fifo` or `error closing exec fds`

Manual or live checks, and anything not tested:

## Reports and compatibility

- [ ] The change does not alter what is sent to AbuseIPDB, or [Data Sent to AbuseIPDB](https://github.com/developingchet/cs-abuseipdb-bouncer#data-sent-to-abuseipdb) is updated to match.
- [ ] A new or changed setting is documented in `docs/CONFIGURATION.md`, `.env.example`, `docker-compose.yml`, the README Configuration Summary and `DOCKERHUB.md`, and behaviour changes have an upgrade note in the README.
- [ ] No API keys appear in code, tests, logs or commits, and new tests and examples use documentation addresses (`203.0.113.0/24`, `198.51.100.0/24`, `2001:db8::/32`).
