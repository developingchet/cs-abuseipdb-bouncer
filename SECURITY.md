# Security Policy

## Supported Versions

Only the latest release receives security fixes. Patch releases are made as needed.

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| Older   | No        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a vulnerability, open a [GitHub Security Advisory](https://github.com/developingchet/cs-abuseipdb-bouncer/security/advisories/new) (private disclosure). GitHub keeps the report confidential until a fix is released.

Include as much of the following as possible:

- A description of the vulnerability and its impact
- The affected component (bouncer binary, Docker image, CI/CD pipeline, etc.)
- Steps to reproduce or a proof-of-concept
- Any suggested mitigations you have identified

You can expect an acknowledgement within **3 business days** and a status update within **7 business days**.

## Disclosure Policy

This project follows [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure):

1. The reporter submits a private advisory.
2. The maintainer triages and confirms the issue.
3. A fix is developed and reviewed privately.
4. A patch release is published.
5. The advisory is made public, crediting the reporter (unless they prefer anonymity).

The target remediation window is **30 days** from confirmed reproduction. Critical vulnerabilities (CVSS ≥ 9.0) are prioritised for faster turnaround.

## Security Properties of This Project

### Runtime Isolation

The Docker image runs with:

- **Distroless base** (`gcr.io/distroless/static-debian12:nonroot`) — no shell, no package manager, no OS utilities
- **UID 65532** (nonroot) — no root access inside or outside the container
- **`cap_drop: ALL`** — no Linux capabilities
- **`read_only: true`** — root filesystem is immutable at runtime
- **`no-new-privileges`** — cannot gain privileges via setuid
- **Seccomp profile** (`security/seccomp-bouncer.json`) — only syscalls required by the binary are permitted

### Secret Handling

- API keys are loaded exclusively from environment variables
- Keys are never written to disk or baked into the image
- A `RedactWriter` wraps stderr and automatically replaces 80-character hex API keys and `Bearer <token>` values with `[REDACTED-API-KEY]` / `bearer [REDACTED]` before they can appear in log output

### Network

- All outbound connections enforce TLS 1.2 as the minimum version
- The AbuseIPDB HTTP client uses a 15-second timeout with exponential backoff retry; it does not make unbounded requests

### Supply-Chain

- Every release tag triggers a GitHub Actions workflow that builds the image, runs Trivy (blocks on HIGH/CRITICAL CVEs), signs the image with [Cosign](https://docs.sigstore.dev/cosign/overview/) (keyless OIDC — no stored private key), and generates a CycloneDX SBOM
- The SBOM is attached to the GitHub Release and embedded as a Cosign attestation on the Docker image
- Verify a release image:

```bash
cosign verify developingchet/cs-abuseipdb-bouncer:<tag> \
  --certificate-identity-regexp="https://github.com/developingchet/cs-abuseipdb-bouncer/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

### Dependency Management

Direct and transitive Go dependencies are tracked in `go.sum`. Trivy scans the final Docker image on every release and blocks publication if HIGH or CRITICAL CVEs are found in unfixed packages.

## Scope

The following are **in scope** for vulnerability reports:

- The Go bouncer binary (`cmd/bouncer`, `internal/`)
- The Dockerfile and runtime container configuration
- The GitHub Actions CI/CD pipeline
- The Docker image published to Docker Hub

The following are **out of scope**:

- The CrowdSec LAPI itself (report to the [CrowdSec security team](https://crowdsec.net/security/))
- The AbuseIPDB API (report to [AbuseIPDB](https://www.abuseipdb.com/contact))
- Denial-of-service attacks that require network access to the metrics port
- Theoretical vulnerabilities with no demonstrated exploit path
