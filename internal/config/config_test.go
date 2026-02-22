package config

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/knadh/koanf/v2"
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

func installConfigSeams(t *testing.T) {
	t.Helper()
	origLoadDefaults := loadDefaultsLayer
	origLoadEnv := loadEnvLayer
	origStat := statFile
	origOpen := openFile
	t.Cleanup(func() {
		loadDefaultsLayer = origLoadDefaults
		loadEnvLayer = origLoadEnv
		statFile = origStat
		openFile = origOpen
	})
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
	assert.Equal(t, 10*time.Second, cfg.PollInterval)
	assert.Equal(t, 10*time.Second, cfg.LAPITimeout)
	assert.Equal(t, 15*time.Minute, cfg.CooldownDuration)
	assert.Equal(t, "/data", cfg.DataDir)
	assert.True(t, cfg.MetricsEnabled)
	assert.Equal(t, ":9090", cfg.MetricsAddr)
	assert.False(t, cfg.TLSSkipVerify)
	assert.True(t, cfg.UsageMetricsEnabled)
	assert.Equal(t, 30*time.Minute, cfg.UsageMetricsInterval)
}

func TestLoad_DefaultLayerError(t *testing.T) {
	installConfigSeams(t)
	loadDefaultsLayer = func(*koanf.Koanf) error {
		return errors.New("defaults exploded")
	}
	setEnv(t, validEnv())

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config: load defaults")
}

func TestLoad_EnvLayerError(t *testing.T) {
	installConfigSeams(t)
	loadEnvLayer = func(*koanf.Koanf) error {
		return errors.New("env exploded")
	}
	setEnv(t, validEnv())

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config: load env")
}

func TestLoad_CustomValues(t *testing.T) {
	env := validEnv()
	env["ABUSEIPDB_DAILY_LIMIT"] = "3000"
	env["ABUSEIPDB_PRECHECK"] = "true"
	env["ABUSEIPDB_MIN_DURATION"] = "300"
	env["LOG_LEVEL"] = "debug"
	env["LOG_FORMAT"] = "text"
	env["POLL_INTERVAL"] = "45s"
	env["LAPI_TIMEOUT"] = "750ms"
	env["COOLDOWN_DURATION"] = "20m"
	env["DATA_DIR"] = "/data/state"
	env["METRICS_ADDR"] = ":9091"
	env["TLS_SKIP_VERIFY"] = "true"
	env["USAGE_METRICS_ENABLED"] = "false"
	env["USAGE_METRICS_INTERVAL"] = "45m"
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, 3000, cfg.DailyLimit)
	assert.True(t, cfg.Precheck)
	assert.Equal(t, 300*time.Second, cfg.MinDuration)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, "text", cfg.LogFormat)
	assert.Equal(t, 45*time.Second, cfg.PollInterval)
	assert.Equal(t, 750*time.Millisecond, cfg.LAPITimeout)
	assert.Equal(t, 20*time.Minute, cfg.CooldownDuration)
	assert.Equal(t, "/data/state", cfg.DataDir)
	assert.Equal(t, ":9091", cfg.MetricsAddr)
	assert.True(t, cfg.TLSSkipVerify)
	assert.False(t, cfg.UsageMetricsEnabled)
	assert.Equal(t, 45*time.Minute, cfg.UsageMetricsInterval)
}

func TestLoad_ConfigFileReadError(t *testing.T) {
	t.Setenv("CONFIG_FILE", filepath.Join(t.TempDir(), "missing.yaml"))
	setEnv(t, validEnv())

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config: load file")
}

func TestLoad_UnmarshalError(t *testing.T) {
	env := validEnv()
	env["POLL_INTERVAL"] = "not-a-duration"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config: unmarshal")
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
		{"missing LAPI auth", "CROWDSEC_LAPI_KEY", "either CROWDSEC_LAPI_KEY"},
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

func TestLoad_LAPIAuthModes(t *testing.T) {
	certPath, keyPath, caPath := writeTLSFiles(t)

	tests := []struct {
		name        string
		env         map[string]string
		wantErr     bool
		errContains string
	}{
		{
			name:    "api key only is valid",
			env:     validEnv(),
			wantErr: false,
		},
		{
			name: "mtls only is valid",
			env: map[string]string{
				"CROWDSEC_LAPI_URL":              "https://crowdsec:8443",
				"CROWDSEC_LAPI_TLS_CERT_PATH":    certPath,
				"CROWDSEC_LAPI_TLS_KEY_PATH":     keyPath,
				"CROWDSEC_LAPI_TLS_CA_CERT_PATH": caPath,
				"ABUSEIPDB_API_KEY":              "test-abuseipdb-key-abcdef1234567890",
			},
			wantErr: false,
		},
		{
			name: "api key and mtls together is invalid",
			env: map[string]string{
				"CROWDSEC_LAPI_URL":           "https://crowdsec:8443",
				"CROWDSEC_LAPI_KEY":           "test-api-key-1234567890abcdef",
				"CROWDSEC_LAPI_TLS_CERT_PATH": "/etc/crowdsec/client.crt",
				"CROWDSEC_LAPI_TLS_KEY_PATH":  "/etc/crowdsec/client.key",
				"ABUSEIPDB_API_KEY":           "test-abuseipdb-key-abcdef1234567890",
			},
			wantErr:     true,
			errContains: "cannot be combined",
		},
		{
			name: "mtls cert without key is invalid",
			env: map[string]string{
				"CROWDSEC_LAPI_URL":           "https://crowdsec:8443",
				"CROWDSEC_LAPI_TLS_CERT_PATH": "/etc/crowdsec/client.crt",
				"ABUSEIPDB_API_KEY":           "test-abuseipdb-key-abcdef1234567890",
			},
			wantErr:     true,
			errContains: "must both be set",
		},
		{
			name: "mtls key without cert is invalid",
			env: map[string]string{
				"CROWDSEC_LAPI_URL":          "https://crowdsec:8443",
				"CROWDSEC_LAPI_TLS_KEY_PATH": "/etc/crowdsec/client.key",
				"ABUSEIPDB_API_KEY":          "test-abuseipdb-key-abcdef1234567890",
			},
			wantErr:     true,
			errContains: "must both be set",
		},
		{
			name: "neither api key nor mtls is invalid",
			env: map[string]string{
				"CROWDSEC_LAPI_URL": "https://crowdsec:8443",
				"ABUSEIPDB_API_KEY": "test-abuseipdb-key-abcdef1234567890",
			},
			wantErr:     true,
			errContains: "either CROWDSEC_LAPI_KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEnv(t, tt.env)
			cfg, err := Load()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cfg)
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

func TestLoad_CooldownDurationTooLow(t *testing.T) {
	env := validEnv()
	env["COOLDOWN_DURATION"] = "30s"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "COOLDOWN_DURATION")
}

func TestLoad_LAPITimeoutTooLow(t *testing.T) {
	env := validEnv()
	env["LAPI_TIMEOUT"] = "199ms"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LAPI_TIMEOUT")
}

func TestLoad_WorkerAndJanitorBounds(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		value  string
		expect string
	}{
		{name: "worker count low", key: "WORKER_COUNT", value: "0", expect: "WORKER_COUNT"},
		{name: "worker buffer low", key: "WORKER_BUFFER", value: "0", expect: "WORKER_BUFFER"},
		{name: "janitor low", key: "JANITOR_INTERVAL", value: "10s", expect: "JANITOR_INTERVAL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnv()
			env[tt.key] = tt.value
			setEnv(t, env)
			_, err := Load()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expect)
		})
	}
}

func TestLoad_UsageMetricsIntervalTooLow(t *testing.T) {
	env := validEnv()
	env["USAGE_METRICS_INTERVAL"] = "5m"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USAGE_METRICS_INTERVAL")
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

func TestLoad_DataDir_NullByteRejected(t *testing.T) {
	cfg := &Config{
		LAPIURL:              "http://crowdsec:8080",
		LAPIKey:              "x",
		AbuseIPDBAPIKey:      "y",
		DailyLimit:           1000,
		PollInterval:         10 * time.Second,
		LAPITimeout:          10 * time.Second,
		CooldownDuration:     time.Minute,
		DataDir:              "bad\x00path",
		WorkerCount:          4,
		WorkerBuffer:         256,
		JanitorInterval:      time.Minute,
		UsageMetricsInterval: 30 * time.Minute,
	}
	err := cfg.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "null bytes")
}

func TestLoad_DataDir_ValidPathAccepted(t *testing.T) {
	env := validEnv()
	env["DATA_DIR"] = "/data" // baseline — must still pass
	setEnv(t, env)
	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "/data", cfg.DataDir)
}

func TestLoad_MinDuration_DurationString(t *testing.T) {
	env := validEnv()
	env["ABUSEIPDB_MIN_DURATION"] = "5m"
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, cfg.MinDuration)
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
			name:        "Invalid CIDR syntax",
			input:       "203.0.113.1/999",
			wantErr:     true,
			errContains: []string{"203.0.113.1/999"},
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
		assert.Contains(t, err.Error(), "either CROWDSEC_LAPI_KEY")
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

func TestLoad_ConfigFilePrecedence(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "bouncer.yaml")
	content := []byte(`
crowdsec_lapi_url: http://from-file:8080
crowdsec_lapi_key: file-key
abuseipdb_api_key: file-abuse-key
poll_interval: 30s
usage_metrics_interval: 31m
`)
	require.NoError(t, os.WriteFile(cfgFile, content, 0o600))

	t.Setenv("CONFIG_FILE", cfgFile)
	t.Setenv("CROWDSEC_LAPI_URL", "http://from-env:8080")
	t.Setenv("CROWDSEC_LAPI_KEY", "env-key")
	t.Setenv("ABUSEIPDB_API_KEY", "env-abuse-key")
	t.Setenv("POLL_INTERVAL", "20s")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "http://from-env:8080", cfg.LAPIURL)
	assert.Equal(t, "env-key", cfg.LAPIKey)
	assert.Equal(t, "env-abuse-key", cfg.AbuseIPDBAPIKey)
	assert.Equal(t, 20*time.Second, cfg.PollInterval)
	assert.Equal(t, 31*time.Minute, cfg.UsageMetricsInterval, "file value should be used when env override absent")
}

func TestLoad_MinDuration_InvalidStringFallsBackToDefault(t *testing.T) {
	env := validEnv()
	env["ABUSEIPDB_MIN_DURATION"] = "not-a-duration"
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), cfg.MinDuration)
}

func TestLoad_MTLSPathValidation(t *testing.T) {
	certPath, keyPath, _ := writeTLSFiles(t)

	t.Run("missing cert file fails", func(t *testing.T) {
		env := map[string]string{
			"CROWDSEC_LAPI_URL":           "https://crowdsec:8443",
			"CROWDSEC_LAPI_TLS_CERT_PATH": filepath.Join(t.TempDir(), "missing.crt"),
			"CROWDSEC_LAPI_TLS_KEY_PATH":  keyPath,
			"ABUSEIPDB_API_KEY":           "test-abuseipdb-key-abcdef1234567890",
		}
		setEnv(t, env)
		_, err := Load()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CROWDSEC_LAPI_TLS_CERT_PATH")
		assert.Contains(t, err.Error(), "not accessible")
	})

	t.Run("missing key file fails", func(t *testing.T) {
		env := map[string]string{
			"CROWDSEC_LAPI_URL":           "https://crowdsec:8443",
			"CROWDSEC_LAPI_TLS_CERT_PATH": certPath,
			"CROWDSEC_LAPI_TLS_KEY_PATH":  filepath.Join(t.TempDir(), "missing.key"),
			"ABUSEIPDB_API_KEY":           "test-abuseipdb-key-abcdef1234567890",
		}
		setEnv(t, env)
		_, err := Load()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CROWDSEC_LAPI_TLS_KEY_PATH")
		assert.Contains(t, err.Error(), "not accessible")
	})

	t.Run("missing ca file fails when configured", func(t *testing.T) {
		env := map[string]string{
			"CROWDSEC_LAPI_URL":              "https://crowdsec:8443",
			"CROWDSEC_LAPI_TLS_CERT_PATH":    certPath,
			"CROWDSEC_LAPI_TLS_KEY_PATH":     keyPath,
			"CROWDSEC_LAPI_TLS_CA_CERT_PATH": filepath.Join(t.TempDir(), "missing-ca.crt"),
			"ABUSEIPDB_API_KEY":              "test-abuseipdb-key-abcdef1234567890",
		}
		setEnv(t, env)
		_, err := Load()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CROWDSEC_LAPI_TLS_CA_CERT_PATH")
		assert.Contains(t, err.Error(), "not accessible")
	})
}

func TestValidateReadableFile(t *testing.T) {
	t.Run("readable file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file.txt")
		require.NoError(t, os.WriteFile(path, []byte("ok"), 0o600))
		require.NoError(t, validateReadableFile(path, "TEST_PATH"))
	})

	t.Run("directory is invalid", func(t *testing.T) {
		dir := t.TempDir()
		err := validateReadableFile(dir, "TEST_PATH")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be a file")
	})

	t.Run("open failure is reported", func(t *testing.T) {
		installConfigSeams(t)
		path := filepath.Join(t.TempDir(), "file.txt")
		require.NoError(t, os.WriteFile(path, []byte("ok"), 0o600))
		openFile = func(string) (*os.File, error) {
			return nil, errors.New("open denied")
		}

		err := validateReadableFile(path, "TEST_PATH")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not readable")
	})
}

func writeTLSFiles(t *testing.T) (certPath string, keyPath string, caPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	caPath = filepath.Join(dir, "ca.crt")

	require.NoError(t, os.WriteFile(certPath, []byte("dummy cert"), 0o600))
	require.NoError(t, os.WriteFile(keyPath, []byte("dummy key"), 0o600))
	require.NoError(t, os.WriteFile(caPath, []byte("dummy ca"), 0o600))
	return certPath, keyPath, caPath
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
