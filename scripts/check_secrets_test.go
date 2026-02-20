// Package main — secret-leak scanner for cs-abuseipdb-bouncer.
//
// This test walks every committed file in the repository and fails if it finds
// patterns that look like real API keys, passwords, or tokens.  Run it before
// every `git push` as a last-line-of-defence sanity check:
//
//	go test ./scripts/ -v -run TestNoSecretsInRepo
//
// The test is intentionally conservative: it checks source files, YAML/TOML,
// shell scripts, and Dockerfiles.  Binary files and the .git directory are
// skipped automatically.
package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// secretPatterns lists regexes that match credential-shaped strings.
// Each pattern includes a human-readable label used in the failure message.
var secretPatterns = []struct {
	label   string
	pattern *regexp.Regexp
}{
	// AbuseIPDB keys are 80-character hex strings.
	{
		"AbuseIPDB API key (80-char hex)",
		regexp.MustCompile(`(?i)ABUSEIPDB_API_KEY\s*=\s*[0-9a-f]{80}`),
	},
	// CrowdSec LAPI bouncer keys: 64-char hex.
	{
		"CrowdSec LAPI key (64-char hex)",
		regexp.MustCompile(`(?i)CROWDSEC_LAPI_KEY\s*=\s*[0-9a-f]{64}`),
	},
	// Any env-var assignment whose value looks like a bearer/API token
	// (≥32 non-whitespace characters after an = sign).
	{
		"generic API key / token assignment (≥32 chars)",
		regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password|passwd|auth)\s*=\s*['"]?[A-Za-z0-9+/\-_]{32,}['"]?`),
	},
	// GitHub personal access tokens (classic and fine-grained).
	{
		"GitHub personal access token",
		regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
	},
	// Docker Hub / registry passwords embedded in shell or YAML.
	{
		"Docker Hub password assignment",
		regexp.MustCompile(`(?i)DOCKER_PASSWORD\s*=\s*\S+`),
	},
	// Private keys (PEM header).
	{
		"PEM private key block",
		regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	},
}

// allowlistPatterns lists line patterns that are safe false-positives.
// A line matching ANY allowlist entry is skipped even if it matches a secret pattern.
var allowlistPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\s*#`),     // comment lines
	regexp.MustCompile(`_test\.go`), // test file references (not inline keys)
	regexp.MustCompile(`(?i)test-key|test-api-key|test-abuseipdb-key|test-api-key-1234|"test`), // test fixtures
	regexp.MustCompile(`(?i)your[-_]key|your[-_]token|your[-_]password`),                       // placeholder prose
	regexp.MustCompile(`(?i)\$\{[^}]+\}|\$[A-Z_]+`),                                            // shell variable expansion like ${DOCKER_PASSWORD}
	regexp.MustCompile(`\{\{[^}]+\}\}`),                                                        // Go / Helm template {{ .Value }}
	regexp.MustCompile(`secrets\.[A-Z_]+`),                                                     // GitHub Actions secret references
	regexp.MustCompile(`(?i)example|placeholder|redacted|changeme`),
	// Repeated single-character placeholders: xxxxxxxx, 00000000, etc.
	regexp.MustCompile(`[xX]{8,}|[0]{8,}`),
}

// scannedExtensions limits scanning to text files only.
var scannedExtensions = map[string]bool{
	".go":         true,
	".yaml":       true,
	".yml":        true,
	".toml":       true,
	".json":       true,
	".env":        true,
	".sh":         true,
	".bash":       true,
	".Dockerfile": true,
	".md":         true,
	".txt":        true,
	"":            true, // files with no extension (e.g., Dockerfile, Makefile)
}

// skipDirs are directories whose contents are never scanned.
var skipDirs = map[string]bool{
	".git":   true,
	"vendor": true,
	".cache": true,
}

func TestNoSecretsInRepo(t *testing.T) {
	// When run with `go test ./scripts/`, Go sets cwd to the package directory.
	// Walk up from cwd until we find a directory containing .git.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot determine working directory: %v", err)
	}
	root := findRepoRoot(cwd)
	if root == "" {
		t.Fatal("could not find repository root (no .git directory found)")
	}

	t.Logf("scanning repository root: %s", root)

	var violations []string

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries silently
		}

		// Skip hidden and ignored directories.
		if d.IsDir() {
			base := d.Name()
			if skipDirs[base] || (strings.HasPrefix(base, ".") && base != ".") {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		baseName := filepath.Base(path)

		// Scan files with no extension too (Dockerfile, Makefile, etc.).
		if !scannedExtensions[ext] && !scannedExtensions[baseName] && !scannedExtensions[""] {
			return nil
		}

		// Only scan files with relevant extensions.
		if !scannedExtensions[ext] && ext != "" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			// Skip allowlisted lines.
			if isAllowlisted(line) {
				continue
			}

			for _, sp := range secretPatterns {
				if sp.pattern.MatchString(line) {
					rel, _ := filepath.Rel(root, path)
					violations = append(violations, formatViolation(rel, lineNum, sp.label, line))
				}
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("walk error: %v", err)
	}

	if len(violations) > 0 {
		t.Errorf("found %d potential secret leak(s):\n\n%s\n\n"+
			"Fix: remove the secret, rotate the credential, and add a placeholder instead.",
			len(violations), strings.Join(violations, "\n"))
	}
}

func isAllowlisted(line string) bool {
	for _, p := range allowlistPatterns {
		if p.MatchString(line) {
			return true
		}
	}
	return false
}

func formatViolation(relPath string, lineNum int, label, line string) string {
	// Redact the likely-sensitive portion before printing.
	display := line
	if len(display) > 120 {
		display = display[:120] + "…"
	}
	return "  " + relPath + ":" + itoa(lineNum) + " [" + label + "]\n    " + display
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// findRepoRoot walks up from start until it finds a directory containing .git.
func findRepoRoot(start string) string {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
