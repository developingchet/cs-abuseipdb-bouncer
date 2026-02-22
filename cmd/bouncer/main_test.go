package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/config"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
)

type stubRuntime struct {
	runFn    func(context.Context) error
	healthFn func(context.Context) error
	closeN   atomic.Int32
}

func (s *stubRuntime) Run(ctx context.Context) error {
	if s.runFn != nil {
		return s.runFn(ctx)
	}
	return nil
}

func (s *stubRuntime) Healthy(ctx context.Context) error {
	if s.healthFn != nil {
		return s.healthFn(ctx)
	}
	return nil
}

func (s *stubRuntime) Close() {
	s.closeN.Add(1)
}

func installMainSeams(t *testing.T) {
	t.Helper()
	origLoad := loadConfig
	origRegister := registerMetrics
	origSignal := newSignalContext
	origNew := newRuntime
	t.Cleanup(func() {
		loadConfig = origLoad
		registerMetrics = origRegister
		newSignalContext = origSignal
		newRuntime = origNew
	})
}

func TestVersionCmd_PrintsVersionInfo(t *testing.T) {
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"version"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "cs-abuseipdb-bouncer")
}

func TestHelpFlag_PrintsUsage(t *testing.T) {
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--help"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Usage")
}

func TestRunBouncer_LoadConfigError(t *testing.T) {
	installMainSeams(t)
	loadConfig = func() (*config.Config, error) {
		return nil, errors.New("bad config")
	}

	err := runBouncer(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configuration error")
}

func TestRunBouncer_RuntimeInitError(t *testing.T) {
	installMainSeams(t)
	loadConfig = func() (*config.Config, error) {
		return &config.Config{LogLevel: "info", LogFormat: "json"}, nil
	}
	registerMetrics = func() {}
	newRuntime = func(cfg *config.Config, sinks []sink.Sink) (runtimeBouncer, error) {
		return nil, errors.New("init fail")
	}
	newSignalContext = func(parent context.Context) (context.Context, context.CancelFunc) {
		return context.WithCancel(parent)
	}

	err := runBouncer(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bouncer init")
}

func TestRunBouncer_RunAndCloseOnCancel(t *testing.T) {
	installMainSeams(t)
	cfg := &config.Config{LogLevel: "debug", LogFormat: "text"}
	loadConfig = func() (*config.Config, error) { return cfg, nil }

	var registered bool
	registerMetrics = func() { registered = true }

	rt := &stubRuntime{}
	rt.runFn = func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}

	var gotVersion string
	newRuntime = func(c *config.Config, sinks []sink.Sink) (runtimeBouncer, error) {
		gotVersion = c.BuildVersion
		return rt, nil
	}
	newSignalContext = func(parent context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(parent)
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		return ctx, func() {}
	}

	err := runBouncer(nil, nil)
	require.NoError(t, err)
	assert.True(t, registered)
	assert.Equal(t, version, gotVersion)
	assert.EqualValues(t, 1, rt.closeN.Load())
}

func TestRunBouncer_PropagatesRunError(t *testing.T) {
	installMainSeams(t)
	loadConfig = func() (*config.Config, error) {
		return &config.Config{LogLevel: "info", LogFormat: "json"}, nil
	}
	registerMetrics = func() {}

	rt := &stubRuntime{
		runFn: func(context.Context) error { return errors.New("run failed") },
	}
	newRuntime = func(cfg *config.Config, sinks []sink.Sink) (runtimeBouncer, error) {
		return rt, nil
	}
	newSignalContext = func(parent context.Context) (context.Context, context.CancelFunc) {
		return context.WithCancel(parent)
	}

	err := runBouncer(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "run failed")
	assert.EqualValues(t, 1, rt.closeN.Load())
}

func TestRunHealthcheck_LoadConfigError(t *testing.T) {
	installMainSeams(t)
	loadConfig = func() (*config.Config, error) {
		return nil, errors.New("bad config")
	}

	err := runHealthcheck(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configuration error")
}

func TestRunHealthcheck_RuntimeInitError(t *testing.T) {
	installMainSeams(t)
	loadConfig = func() (*config.Config, error) {
		return &config.Config{LogFormat: "json"}, nil
	}
	newRuntime = func(cfg *config.Config, sinks []sink.Sink) (runtimeBouncer, error) {
		return nil, errors.New("boom")
	}

	err := runHealthcheck(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestRunHealthcheck_CallsHealthyAndClose(t *testing.T) {
	installMainSeams(t)
	loadConfig = func() (*config.Config, error) {
		return &config.Config{LogFormat: "json"}, nil
	}
	rt := &stubRuntime{
		healthFn: func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			assert.WithinDuration(t, time.Now().Add(10*time.Second), deadline, 500*time.Millisecond)
			return nil
		},
	}
	newRuntime = func(cfg *config.Config, sinks []sink.Sink) (runtimeBouncer, error) {
		return rt, nil
	}

	err := runHealthcheck(nil, nil)
	require.NoError(t, err)
	assert.EqualValues(t, 1, rt.closeN.Load())
}

func TestBuildSinks(t *testing.T) {
	cfg := &config.Config{
		AbuseIPDBAPIKey: "test-key",
		Precheck:        true,
	}
	sinks := buildSinks(cfg)
	require.Len(t, sinks, 1)
	assert.Equal(t, "abuseipdb", sinks[0].Name())
}

func TestInitLogging_SetsExpectedGlobalLevel(t *testing.T) {
	tests := []struct {
		level string
		want  zerolog.Level
	}{
		{level: "trace", want: zerolog.TraceLevel},
		{level: "debug", want: zerolog.DebugLevel},
		{level: "warn", want: zerolog.WarnLevel},
		{level: "warning", want: zerolog.WarnLevel},
		{level: "error", want: zerolog.ErrorLevel},
		{level: "info", want: zerolog.InfoLevel},
		{level: "nope", want: zerolog.InfoLevel},
	}

	for _, tc := range tests {
		t.Run(tc.level, func(t *testing.T) {
			initLogging(tc.level, "json")
			assert.Equal(t, tc.want, zerolog.GlobalLevel())
		})
	}
}

func TestInitLogging_TextFormat(t *testing.T) {
	assert.NotPanics(t, func() {
		initLogging("info", "text")
	})
}

func TestMain_SubprocessVersion_ExitZero(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_SubprocessHelper")
	cmd.Env = append(os.Environ(),
		"GO_WANT_MAIN_PROCESS=1",
		"MAIN_TEST_CASE=version",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Contains(t, string(out), "cs-abuseipdb-bouncer")
}

func TestMain_SubprocessConfigError_ExitOne(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_SubprocessHelper")
	cmd.Env = append(os.Environ(),
		"GO_WANT_MAIN_PROCESS=1",
		"MAIN_TEST_CASE=config-error",
		"CROWDSEC_LAPI_URL=",
		"CROWDSEC_LAPI_KEY=",
		"CROWDSEC_LAPI_KEY_FILE=",
		"ABUSEIPDB_API_KEY=",
		"ABUSEIPDB_API_KEY_FILE=",
	)
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected os.Exit(1)")
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.True(t, strings.Contains(string(out), "fatal") || strings.Contains(string(out), "configuration"))
}

func TestMain_SubprocessHelper(t *testing.T) {
	if os.Getenv("GO_WANT_MAIN_PROCESS") != "1" {
		return
	}

	switch os.Getenv("MAIN_TEST_CASE") {
	case "version":
		os.Args = []string{"cs-abuseipdb-bouncer", "version"}
	case "config-error":
		os.Args = []string{"cs-abuseipdb-bouncer"}
	default:
		t.Fatalf("unknown MAIN_TEST_CASE")
	}

	main()
}

func TestDefaultSeams_AreCallable(t *testing.T) {
	// Exercise default seam implementations so their function literals are covered.
	ctx, cancel := newSignalContext(context.Background())
	cancel()
	<-ctx.Done()

	cfg := &config.Config{
		LAPIURL:          "http://127.0.0.1:8080",
		LAPIKey:          "test-key",
		DailyLimit:       1,
		PollInterval:     10 * time.Second,
		CooldownDuration: time.Minute,
		DataDir:          t.TempDir(),
		WorkerCount:      1,
		WorkerBuffer:     1,
		JanitorInterval:  time.Minute,
	}
	rt, err := newRuntime(cfg, nil)
	require.NoError(t, err)
	rt.Close()
}
