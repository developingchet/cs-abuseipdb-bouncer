package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	for k, v := range vars {
		t.Setenv(k, v)
	}
}

func validEnv() map[string]string {
	return map[string]string{
		"CROWDSEC_LAPI_URL": "http://crowdsec:8080",
		"CROWDSEC_LAPI_KEY": "test-api-key-1234567890abcdef",
		"ABUSEIPDB_API_KEY": "test-abuseipdb-key-abcdef1234567890",
	}
}

func TestLoad_Defaults(t *testing.T) {
	setEnv(t, validEnv())

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "http://crowdsec:8080", cfg.LAPIURL)
	assert.Equal(t, 1000, cfg.DailyLimit)
	assert.False(t, cfg.Precheck)
	assert.Equal(t, time.Duration(0), cfg.MinDuration)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, "json", cfg.LogFormat)
	assert.Equal(t, 30*time.Second, cfg.PollInterval)
	assert.Equal(t, 15*time.Minute, cfg.CooldownDuration)
	assert.Equal(t, "/data", cfg.DataDir)
	assert.Equal(t, ":9090", cfg.MetricsAddr)
	assert.False(t, cfg.TLSSkipVerify)
}

func TestLoad_CustomValues(t *testing.T) {
	env := validEnv()
	env["ABUSEIPDB_DAILY_LIMIT"] = "3000"
	env["ABUSEIPDB_PRECHECK"] = "true"
	env["ABUSEIPDB_MIN_DURATION"] = "300"
	env["LOG_LEVEL"] = "debug"
	env["LOG_FORMAT"] = "text"
	env["POLL_INTERVAL"] = "45s"
	env["COOLDOWN_DURATION"] = "20m"
	env["DATA_DIR"] = "/data/state"
	env["METRICS_ADDR"] = ":9091"
	env["TLS_SKIP_VERIFY"] = "true"
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, 3000, cfg.DailyLimit)
	assert.True(t, cfg.Precheck)
	assert.Equal(t, 300*time.Second, cfg.MinDuration)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, "text", cfg.LogFormat)
	assert.Equal(t, 45*time.Second, cfg.PollInterval)
	assert.Equal(t, 20*time.Minute, cfg.CooldownDuration)
	assert.Equal(t, "/data/state", cfg.DataDir)
	assert.Equal(t, ":9091", cfg.MetricsAddr)
	assert.True(t, cfg.TLSSkipVerify)
}

func TestLoad_StateDirBackwardsCompat(t *testing.T) {
	env := validEnv()
	env["STATE_DIR"] = "/legacy/state"
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "/legacy/state", cfg.DataDir)
}

func TestLoad_MetricsDisabled(t *testing.T) {
	env := validEnv()
	env["METRICS_ADDR"] = ""
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "", cfg.MetricsAddr)
}

func TestLoad_MissingRequired(t *testing.T) {
	tests := []struct {
		name   string
		unset  string
		errMsg string
	}{
		{"missing LAPI URL", "CROWDSEC_LAPI_URL", "CROWDSEC_LAPI_URL is required"},
		{"missing LAPI key", "CROWDSEC_LAPI_KEY", "CROWDSEC_LAPI_KEY is required"},
		{"missing AbuseIPDB key", "ABUSEIPDB_API_KEY", "ABUSEIPDB_API_KEY is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnv()
			delete(env, tt.unset)
			setEnv(t, env)
			os.Unsetenv(tt.unset)

			_, err := Load()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestLoad_InvalidDailyLimit(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"zero", "0"},
		{"negative", "-1"},
		{"too high", "99999"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnv()
			env["ABUSEIPDB_DAILY_LIMIT"] = tt.value
			setEnv(t, env)

			_, err := Load()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "ABUSEIPDB_DAILY_LIMIT")
		})
	}
}

func TestLoad_PollIntervalTooLow(t *testing.T) {
	env := validEnv()
	env["POLL_INTERVAL"] = "5s"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "POLL_INTERVAL")
}

func TestLoad_DataDir_TraversalRejected(t *testing.T) {
	cases := []struct{ name, path string }{
		{"relative traversal", "../../../etc/passwd"},
		{"absolute with dotdot", "/data/../../etc/passwd"},
		{"dotdot only", ".."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := validEnv()
			env["DATA_DIR"] = tc.path
			setEnv(t, env)
			_, err := Load()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "DATA_DIR")
		})
	}
}

func TestLoad_DataDir_ValidPathAccepted(t *testing.T) {
	env := validEnv()
	env["DATA_DIR"] = "/data" // baseline — must still pass
	setEnv(t, env)
	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "/data", cfg.DataDir)
}

func TestEnvBool(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", true},
		{"yes", true},
		{"false", false},
		{"FALSE", false},
		{"0", false},
		{"no", false},
		{"", false},
		{"garbage", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Setenv("TEST_BOOL", tt.input)
			assert.Equal(t, tt.expected, envBool("TEST_BOOL", false))
		})
	}
}
