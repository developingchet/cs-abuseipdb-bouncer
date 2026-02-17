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
2. Verify you're using the latest version
3. Test with `LOG_LEVEL=debug` to gather detailed logs

When submitting a bug report, include:

- Output of `docker logs abuseipdb-bouncer` (sanitize IPs and API keys)
- Output of `docker compose config` (sanitize keys)
- CrowdSec version: `docker exec crowdsec cscli version`
- Your Docker and Docker Compose versions
- Steps to reproduce the issue
- Expected vs. actual behavior

**Security vulnerabilities should be reported privately via email, not as public issues.**

### Suggesting Enhancements

Enhancement suggestions are welcome. When proposing a feature:

1. Check if it's already requested in existing issues
2. Explain the problem you're trying to solve
3. Describe your proposed solution
4. Consider alternative approaches
5. Outline any potential drawbacks or trade-offs

### Improving Documentation

Documentation improvements are highly valued:

- Fix typos or clarify confusing sections
- Add missing examples or use cases
- Update outdated information
- Translate documentation to other languages
- Improve README, setup guides, or troubleshooting docs

Small documentation fixes can be submitted directly as pull requests. For larger changes, open an issue first to discuss.

## Development Setup

### Prerequisites

- Docker 20.10+
- Docker Compose v2+
- Running CrowdSec instance for testing
- AbuseIPDB account (can use free tier)
- Git

### Local Development Environment

1. Fork and clone:
   ```bash
   git clone https://github.com/developingchet/cs-abuseipdb-bouncer.git
   cd cs-abuseipdb-bouncer
   git remote add upstream https://github.com/developingchet/cs-abuseipdb-bouncer.git
   ```

2. Create a development environment file:
   ```bash
   cp .env.example .env.dev
   nano .env.dev
   # Fill in your test API keys
   ```

3. Build and run:
   ```bash
   docker compose build
   docker compose up -d
   ```

4. Follow logs:
   ```bash
   docker logs -f abuseipdb-bouncer
   ```

### Making Changes

1. Create a branch:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

2. Make your changes following the coding standards below

3. Test your changes (see Testing Requirements)

4. Commit with clear messages:
   ```bash
   git add -A
   git commit -m "Add scenario mapping for CVE-2024-12345"
   ```

## Coding Standards

### Shell Script Guidelines

The reporter script follows strict POSIX sh compatibility. Follow these rules:

**1. POSIX Compliance**
- Use `[` not `[[` for tests
- No bash arrays (use space-separated strings)
- No process substitution (use temp files)
- Test with `shellcheck` and `dash`

**2. Variable Declarations**
- Declare all `local` variables at the top of functions
- Assign variables separately from declaration when using command substitution:
  ```bash
  # Correct
  local result
  result=$(command)
  
  # Wrong - masks exit code under set -e
  local result=$(command)
  ```

**3. Quoting**
- Always quote variables: `"$var"`, not `$var`
- Use `printf` instead of `echo` for formatted output
- Quote in case patterns: `"$var")` not `$var)`

**4. Error Handling**
- Scripts should use `set -eu`
- Check return codes explicitly where needed:
  ```bash
  if command; then
      # success
  else
      # failure
  fi
  ```

**5. Comments**
- Comments should explain why, not what
- Section headers use consistent formatting:
  ```bash
  # --- section name -----------------------------------------------
  ```

**6. Logging**
- Use the provided log functions: `info`, `warning`, `error`, `debug`
- Log messages should be concise and include relevant context:
  ```bash
  info "reported ip=${ip} daily=${count}/${limit}"
  ```

### Scenario Mapping Guidelines

When adding new scenario mappings to the `categories()` function:

**1. Pattern Specificity**
- Add specific patterns before generic ones
- Use wildcard matching: `*pattern*`
- Lowercase matching only (script lowercases input)

**2. Category Selection**
- Choose the most specific AbuseIPDB category
- Multiple categories are allowed (comma-separated)
- Refer to: https://www.abuseipdb.com/categories

**3. Testing**
- Test the mapping with a real decision:
  ```bash
  docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -s "yourauthor/your-scenario"
  docker logs -f abuseipdb-bouncer | grep "reporting ip=203.0.113.42"
  ```

**Example:**
```bash
case "$s" in
    # Existing patterns...
    *your-pattern*)  printf '21,20' ;;  # Web App Attack, Exploited Host
    # Generic patterns...
esac
```

### Docker and Compose Standards

**1. Dockerfile**
- Base on official images only
- Minimize layer count
- Use specific version tags (not `latest`)
- Run as non-root user

**2. docker-compose.yml**
- Do not include a `version` field — it is deprecated and ignored in Docker Compose v2
- Include healthchecks
- Provide clear comments for user-editable sections
- Use named volumes for state

## Testing Requirements

### Manual Testing

Before submitting a pull request, test your changes:

**1. Startup Test**
```bash
docker compose build
docker compose up -d
docker logs abuseipdb-bouncer
# Verify: "reporter started" message appears
```

**2. Report Test**
```bash
# Create a test decision
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "test"

# Verify report
docker logs -f abuseipdb-bouncer | grep "203.0.113.42"
# Should see: "reporting ip=203.0.113.42" and "reported ip=203.0.113.42"

# Clean up
docker exec crowdsec cscli decisions delete -i 203.0.113.42
```

**3. Filter Test**
```bash
# Test private IP filtering
docker exec crowdsec cscli decisions add -i 192.168.1.1 -t ban -d 1h

# Enable debug to see skip message
echo "LOG_LEVEL=debug" >> .env
docker compose up -d --force-recreate abuseipdb-bouncer
docker logs -f abuseipdb-bouncer | grep "192.168.1.1"
# Should see: "skip private ip=192.168.1.1"
```

**4. Scenario Mapping Test**

If you added a scenario mapping:
```bash
# Add a decision with your scenario
docker exec crowdsec cscli decisions add -i 203.0.113.50 -t ban -d 1h -s "author/your-scenario"

# Check the categories
docker logs -f abuseipdb-bouncer | grep "your-scenario"
# Should see: "scenario=your-scenario cats=X,Y"

# Verify on AbuseIPDB
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=203.0.113.50" \
  -H "Key: YOUR_KEY" | jq
```

### Automated Testing

Currently, there are no automated tests. Contributions to add test infrastructure are welcome.

**Potential areas:**
- Shell script unit tests with `bats` (Bash Automated Testing System)
- Integration tests with Docker Compose
- Scenario mapping validation script

## Submitting Changes

### Pull Request Process

1. **Update documentation** - If your change affects behavior, update relevant docs

2. **Test thoroughly** - Follow the testing requirements above

3. **Update CHANGELOG** (if exists) - Add a line describing your change

4. **Create pull request**:
   - Use a clear, descriptive title
   - Reference any related issues: "Fixes #123" or "Addresses #456"
   - Describe what changed and why
   - Include testing steps if applicable

5. **Respond to feedback** - Maintainers may request changes

6. **Squash commits** (if requested) - Clean up commit history before merge

### Pull Request Checklist

Before submitting, verify:

- [ ] Code follows the style guidelines
- [ ] All scripts pass `shellcheck` (if modified shell scripts)
- [ ] Manual testing completed successfully
- [ ] Documentation updated (if applicable)
- [ ] No sensitive data (API keys, IPs) in commits
- [ ] Commit messages are clear and descriptive

### Review Process

- Pull requests are reviewed by maintainers
- Feedback is provided within 1 week (usually faster)
- Changes may be requested before merging
- Once approved, maintainers will merge the PR

## Areas Needing Help

We especially welcome contributions in these areas:

### Scenario Mappings

Add mappings for:
- Emerging CVE scenarios
- Vendor-specific attack patterns
- IoT device exploits
- Cloud service abuse scenarios

### Documentation

- Translations (French, German, Spanish, etc.)
- Integration guides (Kubernetes, Proxmox, Synology NAS)
- Video tutorials
- Blog posts or articles about the project

### Testing Infrastructure

- Automated test suite
- CI/CD pipeline (GitHub Actions)
- Multi-architecture Docker builds (ARM, ARM64)

### Features

- Prometheus metrics sidecar
- Web UI for viewing stats
- Custom category mapping via config file
- Webhook notifications

### Performance

- Benchmarking script
- Memory/CPU optimization
- Large-scale deployment guidance

## Getting Help

If you need help contributing:

- Open a discussion: https://github.com/developingchet/cs-abuseipdb-bouncer/discussions
- Ask in CrowdSec Discord: https://discord.gg/crowdsec

## License

By contributing, you agree that your contributions will be licensed under the MIT License (same as the project).
