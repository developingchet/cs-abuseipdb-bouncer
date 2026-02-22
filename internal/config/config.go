package config

import (
	"fmt"
	"net/netip"
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
	LAPIURL         string `koanf:"crowdsec_lapi_url"`
	LAPIKey         string `koanf:"crowdsec_lapi_key"`
	LAPITLSCertPath string `koanf:"crowdsec_lapi_tls_cert_path"`
	LAPITLSKeyPath  string `koanf:"crowdsec_lapi_tls_key_path"`
	LAPITLSCAPath   string `koanf:"crowdsec_lapi_tls_ca_cert_path"`

	// AbuseIPDB
	AbuseIPDBAPIKey string        `koanf:"abuseipdb_api_key"`
	DailyLimit      int           `koanf:"abuseipdb_daily_limit"`
	Precheck        bool          `koanf:"abuseipdb_precheck"`
	MinDuration     time.Duration `koanf:"abuseipdb_min_duration"`

	// Operational
	LogLevel         string        `koanf:"log_level"`
	LogFormat        string        `koanf:"log_format"`
	PollInterval     time.Duration `koanf:"poll_interval"`
	LAPITimeout      time.Duration `koanf:"lapi_timeout"`
	CooldownDuration time.Duration `koanf:"cooldown_duration"`
	DataDir          string        `koanf:"data_dir"` // falls back to STATE_DIR for legacy compatibility
	MetricsEnabled   bool          `koanf:"metrics_enabled"`
	MetricsAddr      string        `koanf:"metrics_addr"` // "" = disabled
	TLSSkipVerify    bool          `koanf:"tls_skip_verify"`

	// Concurrency
	WorkerCount          int           `koanf:"worker_count"`
	WorkerBuffer         int           `koanf:"worker_buffer"`
	JanitorInterval      time.Duration `koanf:"janitor_interval"`
	UsageMetricsEnabled  bool          `koanf:"usage_metrics_enabled"`
	UsageMetricsInterval time.Duration `koanf:"usage_metrics_interval"`

	// Whitelist
	// Raw comma-separated CIDR/IP string from IP_WHITELIST env var.
	WhitelistCIDR string `koanf:"ip_whitelist"`
	// Parsed at startup from WhitelistCIDR. Not loaded by koanf.
	Whitelist []netip.Prefix

	// BuildVersion is injected by main at runtime and is not loaded from env/file.
	BuildVersion string
}

// defaults is the lowest-priority layer.
var defaults = map[string]any{
	"crowdsec_lapi_url":      "",
	"crowdsec_lapi_key":      "",
	"abuseipdb_api_key":      "",
	"abuseipdb_daily_limit":  1000,
	"abuseipdb_precheck":     false,
	"log_level":              "info",
	"log_format":             "json",
	"poll_interval":          10 * time.Second,
	"lapi_timeout":           10 * time.Second,
	"cooldown_duration":      15 * time.Minute,
	"data_dir":               "/data",
	"metrics_enabled":        true,
	"metrics_addr":           ":9090",
	"tls_skip_verify":        false,
	"worker_count":           4,
	"worker_buffer":          256,
	"janitor_interval":       5 * time.Minute,
	"usage_metrics_enabled":  true,
	"usage_metrics_interval": 30 * time.Minute,
}

var (
	loadDefaultsLayer = func(k *koanf.Koanf) error {
		return k.Load(confmap.Provider(defaults, "."), nil)
	}
	loadEnvLayer = func(k *koanf.Koanf) error {
		return k.Load(env.Provider("", ".", envKeyMapper), nil)
	}
	statFile = os.Stat
	openFile = os.Open
)

func envKeyMapper(s string) string {
	if s == "ABUSEIPDB_MIN_DURATION" {
		return "" // skip; handled manually below
	}
	return strings.ToLower(s)
}

// Load reads configuration from (lowest → highest priority):
//  1. Built-in defaults
//  2. YAML file at CONFIG_FILE env var path (if set)
//  3. Environment variables (always highest priority)
func Load() (*Config, error) {
	k := koanf.New(".")

	// Layer 1: defaults.
	if err := loadDefaultsLayer(k); err != nil {
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
	// to support both Go duration strings ("5m") and plain integer seconds ("300").
	if err := loadEnvLayer(k); err != nil {
		return nil, fmt.Errorf("config: load env: %w", err)
	}

	cfg := &Config{}
	if err := k.UnmarshalWithConf("", cfg, koanf.UnmarshalConf{Tag: "koanf"}); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	// Normalise string fields.
	cfg.LogLevel = strings.TrimSpace(strings.ToLower(cfg.LogLevel))
	cfg.LogFormat = strings.TrimSpace(strings.ToLower(cfg.LogFormat))
	cfg.LAPITLSCertPath = strings.TrimSpace(cfg.LAPITLSCertPath)
	cfg.LAPITLSKeyPath = strings.TrimSpace(cfg.LAPITLSKeyPath)
	cfg.LAPITLSCAPath = strings.TrimSpace(cfg.LAPITLSCAPath)

	// ABUSEIPDB_MIN_DURATION: accept both Go duration strings ("5m") and
	// plain integer seconds ("300") for backwards-compatibility.
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

	// Legacy compat: honour STATE_DIR if DATA_DIR is not explicitly set.
	if os.Getenv("DATA_DIR") == "" && os.Getenv("STATE_DIR") != "" {
		cfg.DataDir = os.Getenv("STATE_DIR")
	}

	// Resolve secrets from files (Docker / Kubernetes secrets).
	if v := resolveFileSecret("CROWDSEC_LAPI_KEY"); v != "" {
		cfg.LAPIKey = v
	}
	if v := resolveFileSecret("ABUSEIPDB_API_KEY"); v != "" {
		cfg.AbuseIPDBAPIKey = v
	}

	// METRICS_ENABLED=false disables the server regardless of METRICS_ADDR.
	if !cfg.MetricsEnabled {
		cfg.MetricsAddr = ""
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
	hasAPIKey := strings.TrimSpace(c.LAPIKey) != ""
	hasTLSCert := c.LAPITLSCertPath != ""
	hasTLSKey := c.LAPITLSKeyPath != ""

	if hasAPIKey && (hasTLSCert || hasTLSKey) {
		errs = append(errs, "CROWDSEC_LAPI_KEY cannot be combined with mTLS cert/key; use exactly one auth mode")
	}
	if !hasAPIKey {
		if hasTLSCert != hasTLSKey {
			errs = append(errs, "CROWDSEC_LAPI_TLS_CERT_PATH and CROWDSEC_LAPI_TLS_KEY_PATH must both be set for mTLS auth")
		}
		if !hasTLSCert && !hasTLSKey {
			errs = append(errs, "either CROWDSEC_LAPI_KEY (or CROWDSEC_LAPI_KEY_FILE) or mTLS cert/key paths must be configured")
		}
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
	if c.LAPITimeout < 200*time.Millisecond {
		errs = append(errs, "LAPI_TIMEOUT must be at least 200ms")
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

	if c.WorkerCount < 1 || c.WorkerCount > 64 {
		errs = append(errs, "WORKER_COUNT must be between 1 and 64")
	}
	if c.WorkerBuffer < 1 || c.WorkerBuffer > 10000 {
		errs = append(errs, "WORKER_BUFFER must be between 1 and 10000")
	}
	if c.JanitorInterval < 30*time.Second {
		errs = append(errs, "JANITOR_INTERVAL must be at least 30s")
	}
	if c.UsageMetricsInterval < 10*time.Minute {
		errs = append(errs, "USAGE_METRICS_INTERVAL must be at least 10m")
	}
	if !hasAPIKey && hasTLSCert && hasTLSKey {
		if err := validateReadableFile(c.LAPITLSCertPath, "CROWDSEC_LAPI_TLS_CERT_PATH"); err != nil {
			errs = append(errs, err.Error())
		}
		if err := validateReadableFile(c.LAPITLSKeyPath, "CROWDSEC_LAPI_TLS_KEY_PATH"); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if c.LAPITLSCAPath != "" {
		if err := validateReadableFile(c.LAPITLSCAPath, "CROWDSEC_LAPI_TLS_CA_CERT_PATH"); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if c.WhitelistCIDR != "" {
		parsed, err := parseIPWhitelist(c.WhitelistCIDR)
		if err != nil {
			errs = append(errs, fmt.Sprintf("IP_WHITELIST: %v", err))
		} else {
			c.Whitelist = parsed
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%d configuration error(s):\n  - %s", len(errs), strings.Join(errs, "\n  - "))
	}
	return nil
}

// parseIPWhitelist parses a comma-separated list of IPs and CIDRs into a slice
// of netip.Prefix. Single IPs are promoted to /32 (IPv4) or /128 (IPv6).
// Host bits in CIDR notation are masked (e.g. 192.0.2.5/24 → 192.0.2.0/24).
// Returns an error listing all invalid entries if any are found.
func parseIPWhitelist(raw string) ([]netip.Prefix, error) {
	parts := strings.Split(raw, ",")
	var prefixes []netip.Prefix
	var bad []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			pfx, err := netip.ParsePrefix(p)
			if err != nil {
				bad = append(bad, p)
				continue
			}
			prefixes = append(prefixes, pfx.Masked())
		} else {
			addr, err := netip.ParseAddr(p)
			if err != nil {
				bad = append(bad, p)
				continue
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
		}
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("invalid entries: %s", strings.Join(bad, ", "))
	}
	return prefixes, nil
}

// resolveFileSecret returns the value of envKey if set and non-empty.
// If envKey is unset or empty, it falls back to reading the file at
// envKey+"_FILE" (Docker / Kubernetes secrets convention).
// Returns empty string if neither source provides a value.
func resolveFileSecret(envKey string) string {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	path := strings.TrimSpace(os.Getenv(envKey + "_FILE"))
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
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

func validateReadableFile(path string, envName string) error {
	info, err := statFile(path)
	if err != nil {
		return fmt.Errorf("%s file %q is not accessible: %w", envName, path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s path %q must be a file, not a directory", envName, path)
	}

	f, err := openFile(path)
	if err != nil {
		return fmt.Errorf("%s file %q is not readable: %w", envName, path, err)
	}
	_ = f.Close()
	return nil
}
