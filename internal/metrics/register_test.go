package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestRegister_UsesDefaultRegisterer(t *testing.T) {
	origReg := prometheus.DefaultRegisterer
	origGather := prometheus.DefaultGatherer
	reg := prometheus.NewRegistry()

	prometheus.DefaultRegisterer = reg
	prometheus.DefaultGatherer = reg
	t.Cleanup(func() {
		prometheus.DefaultRegisterer = origReg
		prometheus.DefaultGatherer = origGather
	})

	Register()
	families, err := reg.Gather()
	require.NoError(t, err)
	require.NotEmpty(t, families)
}
