// Package main — CLI integration tests for cs-abuseipdb-bouncer.
//
// Tests exercise the cobra command tree through newRootCmd() so that every
// code path (argument parsing, config loading, error propagation) is covered
// without spawning a subprocess. Tests that trigger config-loading errors are
// safe to run in any environment because they return before opening the bbolt
// database or registering Prometheus metrics.
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVersionCmd_PrintsVersionInfo verifies that the "version" subcommand
// writes the binary name to stdout and exits without error.
func TestVersionCmd_PrintsVersionInfo(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"version"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "cs-abuseipdb-bouncer",
		"version output must include the binary name")
}

// TestHelpFlag_PrintsUsage verifies that --help is handled by cobra without
// returning an error and that the output contains usage information.
func TestHelpFlag_PrintsUsage(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--help"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Usage",
		"--help output must include a Usage section")
}

// TestRunBouncer_MissingConfig_ReturnsConfigError verifies that the root
// command (default "run") surfaces a human-readable configuration error when
// required environment variables are absent, and never panics.
func TestRunBouncer_MissingConfig_ReturnsConfigError(t *testing.T) {
	// Force all three required fields to empty strings so config.Load()
	// returns a validation error before any I/O takes place.
	t.Setenv("CROWDSEC_LAPI_URL", "")
	t.Setenv("CROWDSEC_LAPI_KEY", "")
	t.Setenv("ABUSEIPDB_API_KEY", "")

	cmd := newRootCmd()
	var errBuf bytes.Buffer
	cmd.SetErr(&errBuf)
	cmd.SetArgs([]string{}) // invoke root RunE (runBouncer)

	err := cmd.Execute()
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "configuration error") ||
			strings.Contains(err.Error(), "CROWDSEC_LAPI_URL") ||
			strings.Contains(err.Error(), "ABUSEIPDB_API_KEY"),
		"error must mention the configuration problem; got: %s", err)
}

// TestRunSubcmd_MissingConfig_ReturnsConfigError verifies the explicit "run"
// subcommand behaves identically to the root command on missing config.
func TestRunSubcmd_MissingConfig_ReturnsConfigError(t *testing.T) {
	t.Setenv("CROWDSEC_LAPI_URL", "")
	t.Setenv("CROWDSEC_LAPI_KEY", "")
	t.Setenv("ABUSEIPDB_API_KEY", "")

	cmd := newRootCmd()
	cmd.SetArgs([]string{"run"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configuration error")
}

// TestHealthcheck_MissingConfig_ReturnsConfigError verifies the "healthcheck"
// subcommand surfaces a configuration error when env vars are absent.
func TestHealthcheck_MissingConfig_ReturnsConfigError(t *testing.T) {
	t.Setenv("CROWDSEC_LAPI_URL", "")
	t.Setenv("CROWDSEC_LAPI_KEY", "")
	t.Setenv("ABUSEIPDB_API_KEY", "")

	cmd := newRootCmd()
	cmd.SetArgs([]string{"healthcheck"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configuration error")
}
