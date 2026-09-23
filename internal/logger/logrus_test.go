package logger

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBridgeLogrus_ForwardsEntries(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf)
	BridgeLogrus(&zl)
	t.Cleanup(func() { logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{}) })

	logrus.WithError(errors.New("connection refused")).WithField("attempt", 2).Error("failed to connect to LAPI")

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, "error", got["level"])
	assert.Equal(t, "lapi-client", got["component"])
	assert.Equal(t, "failed to connect to LAPI", got["message"])
	assert.Equal(t, "connection refused", got["error"])
	assert.EqualValues(t, 2, got["attempt"])
}

func TestBridgeLogrus_CapsLibraryAtInfo(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf)
	BridgeLogrus(&zl)
	t.Cleanup(func() { logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{}) })

	// The CrowdSec client dumps requests (with X-Api-Key) at debug/trace.
	assert.False(t, logrus.IsLevelEnabled(logrus.DebugLevel))
	logrus.Debug("dump with X-Api-Key: secret")
	assert.Empty(t, buf.String())
}

func TestZerologLevel(t *testing.T) {
	cases := map[logrus.Level]zerolog.Level{
		logrus.PanicLevel: zerolog.PanicLevel,
		logrus.FatalLevel: zerolog.FatalLevel,
		logrus.ErrorLevel: zerolog.ErrorLevel,
		logrus.WarnLevel:  zerolog.WarnLevel,
		logrus.InfoLevel:  zerolog.InfoLevel,
		logrus.DebugLevel: zerolog.DebugLevel,
		logrus.TraceLevel: zerolog.TraceLevel,
	}
	for in, want := range cases {
		assert.Equal(t, want, zerologLevel(in), in.String())
	}
	assert.Len(t, logrusBridge{}.Levels(), len(logrus.AllLevels))
}
