package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config holds all runtime configuration.
type Config struct {
	// CrowdSec LAPI connection
	LAPIURL string `koanf:"crowdsec_lapi_url"`
	LAPIKey string `koanf:"crowdsec_lapi_key"`

	// AbuseIPDB
	AbuseIPDBAPIKey string        `koanf:"abuseipdb_api_key"`
	DailyLimit      int           `koanf:"abuseipdb_daily_limit"`
	Precheck        bool          `koanf:"abuseipdb_precheck"`
	MinDuration     time.Duration `koanf:"abuseipdb_min_duration"`

	// Operational
	LogLevel         string        `koanf:"log_level"`
	LogFormat        string        `koanf:"log_format"`
	PollInterval     time.Duration `koanf:"poll_interval"`
	CooldownDuration time.Duration `koanf:"cooldown_duration"`
	DataDir          string        `koanf:"data_dir"`     // was STATE_DIR/StateDir
	MetricsAddr      string        `koanf:"metrics_addr"` // NEW: "" = disabled
	TLSSkipVerify    bool          `koanf:"tls_skip_verify"`
}

// defaults is the lowest-priority layer.
var defaults = map[string]any{
	"crowdsec_lapi_url":     "",
	"crowdsec_lapi_key":     "",
	"abuseipdb_api_key":     "",
	"abuseipdb_daily_limit": 1000,
	"abuseipdb_precheck":    false,
	"log_level":             "info",
	"log_format":            "json",
	"poll_interval":         30 * time.Second,
	"cooldown_duration":     15 * time.Minute,
	"data_dir":              "/data",
	"metrics_addr":          ":9090",
	"tls_skip_verify":       false,
}

// Load reads configuration from (lowest → highest priority):
//  1. Built-in defaults
//  2. YAML file at CONFIG_FILE env var path (if set)
//  3. Environment variables (always highest priority)
func Load() (*Config, error) {
	k := koanf.New(".")

	// Layer 1: defaults.
	if err := k.Load(confmap.Provider(defaults, "."), nil); err != nil {
		return nil, fmt.Errorf("config: load defaults: %w", err)
	}

	// Layer 2: optional YAML file.
	if cfgFile := os.Getenv("CONFIG_FILE"); cfgFile != "" {
		if err := k.Load(file.Provider(cfgFile), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("config: load file %s: %w", cfgFile, err)
		}
	}

	// Layer 3: environment variables.
	// Transform: "CROWDSEC_LAPI_URL" → "crowdsec_lapi_url".
	// ABUSEIPDB_MIN_DURATION is intentionally skipped here and handled below
	// for v1 backwards-compatibility (v1 used plain integers for seconds).
	if err := k.Load(env.Provider("", ".", func(s string) string {
		if s == "ABUSEIPDB_MIN_DURATION" {
			return "" // skip; handled manually below
		}
		return strings.ToLower(s)
	}), nil); err != nil {
		return nil, fmt.Errorf("config: load env: %w", err)
	}

	cfg := &Config{}
	if err := k.UnmarshalWithConf("", cfg, koanf.UnmarshalConf{Tag: "koanf"}); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	// Normalise string fields.
	cfg.LogLevel = strings.TrimSpace(strings.ToLower(cfg.LogLevel))
	cfg.LogFormat = strings.TrimSpace(strings.ToLower(cfg.LogFormat))

	// ABUSEIPDB_MIN_DURATION: accept both Go duration strings ("5m") and
	// plain integer seconds ("300") for v1 backwards-compatibility.
	if raw := strings.TrimSpace(os.Getenv("ABUSEIPDB_MIN_DURATION")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			cfg.MinDuration = d
		} else {
			var secs int64
			if _, err := fmt.Sscanf(raw, "%d", &secs); err == nil {
				cfg.MinDuration = time.Duration(secs) * time.Second
			}
		}
	}

	// v1 compat: honour STATE_DIR if DATA_DIR is not explicitly set.
	if os.Getenv("DATA_DIR") == "" && os.Getenv("STATE_DIR") != "" {
		cfg.DataDir = os.Getenv("STATE_DIR")
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	var errs []string

	if c.LAPIURL == "" {
		errs = append(errs, "CROWDSEC_LAPI_URL is required (e.g., http://crowdsec:8080)")
	}
	if c.LAPIKey == "" {
		errs = append(errs, "CROWDSEC_LAPI_KEY is required (run: docker exec crowdsec cscli bouncers add abuseipdb-bouncer)")
	}
	if c.AbuseIPDBAPIKey == "" {
		errs = append(errs, "ABUSEIPDB_API_KEY is required (get your key at: https://www.abuseipdb.com/account/api)")
	}
	if c.DailyLimit < 1 || c.DailyLimit > 50000 {
		errs = append(errs, "ABUSEIPDB_DAILY_LIMIT must be between 1 and 50000")
	}
	if c.PollInterval < 10*time.Second {
		errs = append(errs, "POLL_INTERVAL must be at least 10s")
	}
	if c.CooldownDuration < 1*time.Minute {
		errs = append(errs, "COOLDOWN_DURATION must be at least 1m")
	}

	// DataDir path sanitisation: reject traversal sequences and null bytes.
	if strings.Contains(c.DataDir, "..") {
		errs = append(errs, `DATA_DIR must not contain ".." (directory traversal)`)
	}
	if strings.ContainsRune(c.DataDir, 0) {
		errs = append(errs, "DATA_DIR must not contain null bytes")
	}

	if len(errs) > 0 {
		return fmt.Errorf("%d configuration error(s):\n  - %s", len(errs), strings.Join(errs, "\n  - "))
	}
	return nil
}

// envBool is kept for the TestEnvBool test.
func envBool(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	switch v {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return fallback
	}
}
