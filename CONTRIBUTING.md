# Contributing Guidelines

Thank you for considering contributing to the CrowdSec AbuseIPDB Bouncer project. This document outlines the process for contributing and provides guidelines to ensure quality and consistency.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Submitting Changes](#submitting-changes)
- [Areas Needing Help](#areas-needing-help)

## Code of Conduct

This project follows the principles of respectful, inclusive collaboration:

- Be respectful and constructive in all interactions
- Welcome newcomers and provide helpful feedback
- Focus on what is best for the community and the project
- Assume good faith and be patient with misunderstandings

## How to Contribute

### Reporting Bugs

Before reporting a bug:

1. Check existing issues: https://github.com/developingchet/cs-abuseipdb-bouncer/issues
2. Verify you are using the latest version
3. Enable debug logging to gather detailed output: `LOG_LEVEL=debug`

When submitting a bug report, include:

- Output of `docker logs abuseipdb-bouncer` (sanitize IPs and API keys)
- Output of `docker inspect abuseipdb-bouncer` (sanitize keys)
- CrowdSec version: `docker exec crowdsec cscli version`
- Your Docker and Docker Compose versions
- Steps to reproduce the issue
- Expected vs. actual behavior

Security vulnerabilities should be reported privately via email, not as public issues.

### Suggesting Enhancements

Enhancement suggestions are welcome. When proposing a feature:

1. Check if it is already requested in existing issues
2. Explain the problem you are trying to solve
3. Describe your proposed solution
4. Consider alternative approaches
5. Outline any potential drawbacks or trade-offs

### Improving Documentation

Documentation improvements are highly valued:

- Fix typos or clarify confusing sections
- Add missing examples or use cases
- Update outdated information
- Improve README, setup guides, or troubleshooting docs

Small documentation fixes can be submitted directly as pull requests. For larger changes, open an issue first to discuss.

## Development Setup

### Prerequisites

- Go 1.23 or higher (`go version`)
- Docker 20.10+ and Docker Compose v2+
- Git

Go is required for local development and running tests. Docker is used for building the final image. A live CrowdSec instance is not required for unit tests -- all external dependencies are mocked.

### Local Development Environment

1. Fork and clone:
   ```bash
   git clone https://github.com/developingchet/cs-abuseipdb-bouncer.git
   cd cs-abuseipdb-bouncer
   git remote add upstream https://github.com/developingchet/cs-abuseipdb-bouncer.git
   ```

2. Download dependencies:
   ```bash
   go mod download
   ```

3. Run tests:
   ```bash
   go test ./...
   ```

4. Build the binary:
   ```bash
   go build -o bouncer ./cmd/bouncer/
   ```

5. Build the Docker image:
   ```bash
   docker compose build
   ```

### Making Changes

1. Create a branch:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

2. Make your changes following the coding standards below

3. Run tests and verify they pass:
   ```bash
   go test ./...
   go test -race ./...
   ```

4. Commit with clear messages:
   ```bash
   git add internal/path/to/file.go
   git commit -m "Add scenario mapping for CVE-2024-12345"
   ```

## Coding Standards

### Go Guidelines

The project follows standard Go conventions enforced by `gofmt` and `go vet`.

**Formatting**

All code must be formatted with `gofmt`:
```bash
gofmt -w ./...
```

**Error handling**

Return errors; do not panic. Wrap errors with context:
```go
if err := os.WriteFile(path, data, 0o600); err != nil {
    return fmt.Errorf("writing cooldown file %s: %w", path, err)
}
```

**Logging**

Use the zerolog package-level logger. Include relevant fields as key-value pairs:
```go
log.Info().Str("ip", ip).Int("daily", count).Msg("reported")
log.Debug().Str("filter", reason.Filter).Str("detail", reason.Detail).Msg("decision filtered")
```

Do not log API keys, passwords, or other secrets. Do not format variables into message strings -- use structured fields.

**Tests**

Every new exported function must have a test. Use table-driven tests and `t.TempDir()` for filesystem isolation:
```go
func TestMyFunction(t *testing.T) {
    tests := []struct {
        name  string
        input string
        want  string
    }{
        {"basic case", "input", "expected"},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := MyFunction(tt.input)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

**No new dependencies without discussion**

Adding a `go.mod` dependency requires prior discussion in the issue tracker. The dependency list is intentionally small to minimize supply chain risk.

### Scenario Mapping Guidelines

When adding new scenario mappings to `internal/sink/abuseipdb/mapper.go`:

**Pattern specificity**
- Add specific patterns before generic ones -- the first match wins
- Patterns are compared as substrings after lowercasing and stripping the author prefix
- Test that your pattern does not shadow an existing higher-priority rule

**Category selection**
- Choose the most specific applicable AbuseIPDB category
- Multiple categories are allowed
- Refer to: https://www.abuseipdb.com/categories

**Add a test case** in `mapper_test.go`:
```go
{"crowdsecurity/my-new-scenario", []int{21, 20}},
```

### Docker and Compose Standards

**Dockerfile**
- Builder stage: `golang:1.23-alpine`
- Runtime stage: `gcr.io/distroless/static-debian12:nonroot`
- Build flags: `CGO_ENABLED=0 -ldflags="-s -w" -trimpath`
- Do not add runtime dependencies (curl, wget, jq, etc.)

**docker-compose.yml**
- Do not include a `version` field -- it is deprecated and ignored in Docker Compose v2
- Maintain `read_only: true`, `cap_drop: [ALL]`, and `no-new-privileges`
- Provide clear comments for user-editable sections

## Testing Requirements

### Unit Tests

All unit tests run without network access or external services:

```bash
# Run all tests
go test ./...

# With race detector
go test -race ./...

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Manual Testing

Before submitting a pull request:

**Build test:**
```bash
docker compose build
docker compose up -d
docker logs abuseipdb-bouncer
# Verify: bouncer started message appears
```

**Report test:**
```bash
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "test"
docker logs -f abuseipdb-bouncer | grep 203.0.113.42
# Verify: "reported" log line appears
docker exec crowdsec cscli decisions delete -i 203.0.113.42
```

**Filter test:**
```bash
LOG_LEVEL=debug docker compose up -d --force-recreate abuseipdb-bouncer
docker exec crowdsec cscli decisions add -i 192.168.1.1 -t ban -d 1h
docker logs -f abuseipdb-bouncer | grep 192.168.1.1
# Verify: "decision filtered" with filter=private-ip
```

## Submitting Changes

### Pull Request Process

1. **Update documentation** -- if your change affects behavior, update the relevant docs

2. **Test thoroughly** -- follow the testing requirements above

3. **Create pull request**:
   - Use a clear, descriptive title
   - Reference any related issues: "Fixes #123" or "Addresses #456"
   - Describe what changed and why
   - Include testing steps if applicable

4. **Respond to feedback** -- maintainers may request changes

5. **Squash commits** (if requested) -- clean up commit history before merge

### Pull Request Checklist

Before submitting, verify:

- [ ] Code is formatted with `gofmt`
- [ ] `go test ./...` passes
- [ ] `go test -race ./...` passes (no data races)
- [ ] `go vet ./...` reports no issues
- [ ] Documentation updated if applicable
- [ ] No sensitive data (API keys, real IP addresses) in commits
- [ ] Commit messages are clear and descriptive

### Review Process

- Pull requests are reviewed by maintainers
- Feedback is provided within one week (usually faster)
- Changes may be requested before merging
- Once approved, maintainers will merge the PR

## Areas Needing Help

### Scenario Mappings

Add mappings for:
- Emerging CVE scenarios
- Vendor-specific attack patterns
- IoT device exploits
- Cloud service abuse scenarios

### Documentation

- Translations (French, German, Spanish, etc.)
- Integration guides (Kubernetes, Proxmox, Synology NAS)
- Blog posts or articles about the project

### Testing Infrastructure

- CI/CD pipeline (GitHub Actions)
- Multi-architecture Docker builds (ARM, ARM64)

### Features

- Prometheus metrics endpoint
- Custom category mapping via configuration file
- Webhook notifications for quota warnings

## Getting Help

If you need help contributing:

- Open a discussion: https://github.com/developingchet/cs-abuseipdb-bouncer/discussions
- Ask in CrowdSec Discord: https://discord.gg/crowdsec

## License

By contributing, you agree that your contributions will be licensed under the MIT License (same as the project).
