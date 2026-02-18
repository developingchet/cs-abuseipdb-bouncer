package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/bouncer"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/config"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/logger"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/metrics"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
	abuseipdb "github.com/developingchet/cs-abuseipdb-bouncer/internal/sink/abuseipdb"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		log.Error().Err(err).Msg("fatal")
		os.Exit(1)
	}
}

// newRootCmd builds and returns the root cobra command. Extracted from main so
// that tests can invoke it directly without spawning a subprocess.
func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "cs-abuseipdb-bouncer",
		Short: "Report CrowdSec decisions to AbuseIPDB",
		Long: `A standalone CrowdSec bouncer that polls the Local API for decisions
and reports malicious IPs to AbuseIPDB in real-time.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          runBouncer,
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "run",
		Short: "Start the bouncer (same as running without a subcommand)",
		RunE:  runBouncer,
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "healthcheck",
		Short: "Check LAPI and AbuseIPDB connectivity (for Docker HEALTHCHECK)",
		RunE:  runHealthcheck,
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "cs-abuseipdb-bouncer %s (commit: %s, built: %s)\n", version, commit, date)
		},
	})

	return rootCmd
}

func runBouncer(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	initLogging(cfg.LogLevel, cfg.LogFormat)

	metrics.Register()

	sinks := buildSinks(cfg)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	b, err := bouncer.New(cfg, sinks)
	if err != nil {
		return fmt.Errorf("bouncer init: %w", err)
	}
	defer b.Close()

	return b.Run(ctx)
}

func runHealthcheck(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	initLogging("error", cfg.LogFormat)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sinks := buildSinks(cfg)
	b, err := bouncer.New(cfg, sinks)
	if err != nil {
		return err
	}
	defer b.Close()
	return b.Healthy(ctx)
}

// buildSinks creates the ordered list of report sinks from configuration.
func buildSinks(cfg *config.Config) []sink.Sink {
	return []sink.Sink{
		abuseipdb.NewClient(abuseipdb.ClientConfig{
			APIKey:   cfg.AbuseIPDBAPIKey,
			Precheck: cfg.Precheck,
		}),
	}
}

func initLogging(level string, format string) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	redacted := logger.NewRedactWriter(os.Stderr)
	if format == "text" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: redacted})
	} else {
		log.Logger = zerolog.New(redacted).With().Timestamp().Logger()
	}

	// go-cs-bouncer uses logrus internally. Silence it so its text-format lines
	// don't appear mixed in with our structured JSON output. Errors from the
	// bouncer library are returned as Go errors and logged via zerolog below.
	logrus.SetOutput(io.Discard)

	switch level {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "warn", "warning":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}
