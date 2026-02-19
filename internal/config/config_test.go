package config

import (
	"net/netip"
	"os"
	"path/filepath"
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
	assert.True(t, cfg.MetricsEnabled)
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

func TestLoad_MetricsEnabled(t *testing.T) {
	t.Run("disabled via flag", func(t *testing.T) {
		env := validEnv()
		env["METRICS_ENABLED"] = "false"
		setEnv(t, env)

		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, "", cfg.MetricsAddr)
	})

	t.Run("flag overrides explicit addr", func(t *testing.T) {
		env := validEnv()
		env["METRICS_ENABLED"] = "false"
		env["METRICS_ADDR"] = ":9091"
		setEnv(t, env)

		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, "", cfg.MetricsAddr)
	})

	t.Run("enabled explicitly", func(t *testing.T) {
		env := validEnv()
		env["METRICS_ENABLED"] = "true"
		setEnv(t, env)

		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, ":9090", cfg.MetricsAddr)
	})

	t.Run("unset defaults to enabled", func(t *testing.T) {
		setEnv(t, validEnv())

		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, ":9090", cfg.MetricsAddr)
	})
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

func TestParseIPWhitelist(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		want        []netip.Prefix
		wantErr     bool
		errContains []string
	}{
		{
			name:  "Single IPv4",
			input: "203.0.113.42",
			want:  []netip.Prefix{netip.MustParsePrefix("203.0.113.42/32")},
		},
		{
			name:  "Single IPv6",
			input: "2001:db8::1",
			want:  []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")},
		},
		{
			name:  "IPv4 CIDR",
			input: "203.0.113.0/24",
			want:  []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		},
		{
			name:  "CIDR with host bits masked",
			input: "203.0.113.5/24",
			want:  []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		},
		{
			name:  "Mixed valid entries",
			input: "203.0.113.0/24, 198.51.100.7",
			want: []netip.Prefix{
				netip.MustParsePrefix("203.0.113.0/24"),
				netip.MustParsePrefix("198.51.100.7/32"),
			},
		},
		{
			name:        "Single invalid",
			input:       "notanip",
			wantErr:     true,
			errContains: []string{"notanip"},
		},
		{
			name:        "Mixed valid and invalid",
			input:       "203.0.113.0/24,bad,198.51.100.7,also-bad",
			wantErr:     true,
			errContains: []string{"bad", "also-bad"},
		},
		{
			name:  "Empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "Only commas and spaces",
			input: " , , ",
			want:  nil,
		},
		{
			name:  "IPv6 CIDR",
			input: "2001:db8::/32",
			want:  []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIPWhitelist(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				for _, s := range tt.errContains {
					assert.Contains(t, err.Error(), s)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoad_Whitelist(t *testing.T) {
	t.Run("valid whitelist is parsed", func(t *testing.T) {
		env := validEnv()
		env["IP_WHITELIST"] = "203.0.113.0/24,198.51.100.7"
		setEnv(t, env)

		cfg, err := Load()
		require.NoError(t, err)
		require.Len(t, cfg.Whitelist, 2)
		assert.Equal(t, netip.MustParsePrefix("203.0.113.0/24"), cfg.Whitelist[0])
		assert.Equal(t, netip.MustParsePrefix("198.51.100.7/32"), cfg.Whitelist[1])
	})

	t.Run("invalid whitelist causes error", func(t *testing.T) {
		env := validEnv()
		env["IP_WHITELIST"] = "notanip"
		setEnv(t, env)

		_, err := Load()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "IP_WHITELIST")
		assert.Contains(t, err.Error(), "notanip")
	})

	t.Run("unset whitelist is nil", func(t *testing.T) {
		setEnv(t, validEnv())

		cfg, err := Load()
		require.NoError(t, err)
		assert.Nil(t, cfg.Whitelist)
	})
}

func TestLoad_FileSecret(t *testing.T) {
	t.Run("CROWDSEC_LAPI_KEY_FILE provides key when direct var unset", func(t *testing.T) {
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "lapi_key")
		require.NoError(t, os.WriteFile(keyFile, []byte("my-lapi-key-from-file"), 0o600))

		env := validEnv()
		delete(env, "CROWDSEC_LAPI_KEY")
		setEnv(t, env)
		os.Unsetenv("CROWDSEC_LAPI_KEY")
		t.Setenv("CROWDSEC_LAPI_KEY_FILE", keyFile)

		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, "my-lapi-key-from-file", cfg.LAPIKey)
	})

	t.Run("ABUSEIPDB_API_KEY_FILE provides key when direct var unset", func(t *testing.T) {
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "abuseipdb_key")
		require.NoError(t, os.WriteFile(keyFile, []byte("my-abuseipdb-key-from-file"), 0o600))

		env := validEnv()
		delete(env, "ABUSEIPDB_API_KEY")
		setEnv(t, env)
		os.Unsetenv("ABUSEIPDB_API_KEY")
		t.Setenv("ABUSEIPDB_API_KEY_FILE", keyFile)

		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, "my-abuseipdb-key-from-file", cfg.AbuseIPDBAPIKey)
	})

	t.Run("direct env var wins over _FILE", func(t *testing.T) {
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "lapi_key")
		require.NoError(t, os.WriteFile(keyFile, []byte("from-file"), 0o600))

		env := validEnv()
		env["CROWDSEC_LAPI_KEY"] = "direct-key-value"
		setEnv(t, env)
		t.Setenv("CROWDSEC_LAPI_KEY_FILE", keyFile)

		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, "direct-key-value", cfg.LAPIKey)
	})

	t.Run("nonexistent _FILE path fails with required error", func(t *testing.T) {
		env := validEnv()
		delete(env, "CROWDSEC_LAPI_KEY")
		setEnv(t, env)
		os.Unsetenv("CROWDSEC_LAPI_KEY")
		t.Setenv("CROWDSEC_LAPI_KEY_FILE", "/nonexistent/path/to/key")

		_, err := Load()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CROWDSEC_LAPI_KEY is required")
	})

	t.Run("file with surrounding whitespace is trimmed", func(t *testing.T) {
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "lapi_key")
		require.NoError(t, os.WriteFile(keyFile, []byte("  my-key-with-spaces\n"), 0o600))

		env := validEnv()
		delete(env, "CROWDSEC_LAPI_KEY")
		setEnv(t, env)
		os.Unsetenv("CROWDSEC_LAPI_KEY")
		t.Setenv("CROWDSEC_LAPI_KEY_FILE", keyFile)

		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, "my-key-with-spaces", cfg.LAPIKey)
	})
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
