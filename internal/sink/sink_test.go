// Package sink_test verifies the Report struct and the Sink interface contract.
//
// The sink package contains only type definitions — no logic to test — so the
// goals here are:
//  1. Compile-time proof that a concrete struct satisfies the Sink interface.
//  2. Basic field-access tests that will catch any accidental renaming or
//     type changes to Report during refactoring.
package sink_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
)

// stubSink is a minimal no-op implementation used only to assert interface
// compliance at compile time.
type stubSink struct{}

func (s *stubSink) Name() string                                    { return "stub" }
func (s *stubSink) Report(_ context.Context, _ *sink.Report) error { return nil }
func (s *stubSink) Healthy(_ context.Context) error                 { return nil }
func (s *stubSink) Close() error                                    { return nil }

// Compile-time assertion: stubSink must satisfy sink.Sink.
var _ sink.Sink = (*stubSink)(nil)

// TestReport_ZeroValue checks that the zero value of Report has the expected
// empty/zero fields, ensuring no unexpected defaults are introduced.
func TestReport_ZeroValue(t *testing.T) {
	r := sink.Report{}
	assert.Empty(t, r.IP)
	assert.Zero(t, r.DecisionID)
	assert.Empty(t, r.Scenario)
	assert.Zero(t, r.Duration)
}

// TestReport_FieldAssignment verifies that every field in Report can be
// written and read back correctly.
func TestReport_FieldAssignment(t *testing.T) {
	r := sink.Report{
		IP:         "203.0.113.42",
		DecisionID: 12345,
		Scenario:   "crowdsecurity/ssh-bf",
		Duration:   24 * time.Hour,
	}

	assert.Equal(t, "203.0.113.42", r.IP)
	assert.Equal(t, int64(12345), r.DecisionID)
	assert.Equal(t, "crowdsecurity/ssh-bf", r.Scenario)
	assert.Equal(t, 24*time.Hour, r.Duration)
}
