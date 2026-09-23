package logger

import (
	"io"

	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
)

// logrusBridge forwards logrus entries (emitted by go-cs-bouncer and the
// CrowdSec API client) into a zerolog logger, so LAPI errors appear in the
// same structured, redacted stream as the bouncer's own logs.
type logrusBridge struct {
	log *zerolog.Logger
}

func (logrusBridge) Levels() []logrus.Level { return logrus.AllLevels }

func (b logrusBridge) Fire(e *logrus.Entry) error {
	ev := b.log.WithLevel(zerologLevel(e.Level)).Str("component", "lapi-client")
	for k, v := range e.Data {
		if err, ok := v.(error); ok {
			ev = ev.AnErr(k, err)
			continue
		}
		ev = ev.Interface(k, v)
	}
	ev.Msg(e.Message)
	return nil
}

// BridgeLogrus routes the standard logrus logger into dst. logrus's own
// writer is discarded so nothing is printed twice or unformatted.
func BridgeLogrus(dst *zerolog.Logger) {
	std := logrus.StandardLogger()
	std.SetOutput(io.Discard)
	std.ReplaceHooks(logrus.LevelHooks{})
	std.AddHook(logrusBridge{log: dst})
	// Cap library output at Info: at debug/trace the CrowdSec API client dumps
	// full HTTP requests and responses, including the X-Api-Key header.
	std.SetLevel(logrus.InfoLevel)
}

func zerologLevel(l logrus.Level) zerolog.Level {
	switch l {
	case logrus.PanicLevel:
		return zerolog.PanicLevel
	case logrus.FatalLevel:
		return zerolog.FatalLevel
	case logrus.ErrorLevel:
		return zerolog.ErrorLevel
	case logrus.WarnLevel:
		return zerolog.WarnLevel
	case logrus.InfoLevel:
		return zerolog.InfoLevel
	case logrus.DebugLevel:
		return zerolog.DebugLevel
	default:
		return zerolog.TraceLevel
	}
}
