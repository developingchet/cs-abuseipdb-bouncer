package bouncer

import (
	"io"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestMain(m *testing.M) {
	orig := log.Logger
	log.Logger = zerolog.New(io.Discard)
	code := m.Run()
	log.Logger = orig
	os.Exit(code)
}
