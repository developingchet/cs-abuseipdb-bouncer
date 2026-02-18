package decision

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestActionFilter(t *testing.T) {
	f := ActionFilter("add")

	assert.Nil(t, f(&Decision{Action: "add"}))
	assert.NotNil(t, f(&Decision{Action: "del"}))
	assert.NotNil(t, f(&Decision{Action: "delete"}))
	assert.NotNil(t, f(&Decision{Action: ""}))
}

func TestScenarioExclude(t *testing.T) {
	f := ScenarioExclude("impossible-travel", "impossible_travel")

	assert.NotNil(t, f(&Decision{Scenario: "crowdsecurity/impossible-travel"}))
	assert.NotNil(t, f(&Decision{Scenario: "crowdsecurity/impossible_travel"}))
	assert.NotNil(t, f(&Decision{Scenario: "myorg/Impossible-Travel-Detection"}))
	assert.Nil(t, f(&Decision{Scenario: "crowdsecurity/ssh-bf"}))
	assert.Nil(t, f(&Decision{Scenario: "crowdsecurity/http-probing"}))
}

func TestOriginAllow(t *testing.T) {
	f := OriginAllow("crowdsec", "cscli")

	assert.Nil(t, f(&Decision{Origin: "crowdsec"}))
	assert.Nil(t, f(&Decision{Origin: "cscli"}))
	assert.NotNil(t, f(&Decision{Origin: "CAPI"}))
	assert.NotNil(t, f(&Decision{Origin: "lists"}))
	assert.NotNil(t, f(&Decision{Origin: ""}))
}

func TestScopeAllow(t *testing.T) {
	f := ScopeAllow("ip")

	assert.Nil(t, f(&Decision{Scope: "Ip"}))
	assert.Nil(t, f(&Decision{Scope: "ip"}))
	assert.Nil(t, f(&Decision{Scope: "IP"}))
	assert.NotNil(t, f(&Decision{Scope: "Range"}))
	assert.NotNil(t, f(&Decision{Scope: "AS"}))
	assert.NotNil(t, f(&Decision{Scope: "Country"}))
	assert.NotNil(t, f(&Decision{Scope: ""}))
}

func TestValueRequired(t *testing.T) {
	f := ValueRequired()

	assert.Nil(t, f(&Decision{Value: "203.0.113.42"}))
	assert.Nil(t, f(&Decision{Value: "2001:db8::1"}))
	assert.NotNil(t, f(&Decision{Value: ""}))
	assert.NotNil(t, f(&Decision{Value: "   "}))
}

func TestPrivateIPReject(t *testing.T) {
	f := PrivateIPReject()

	// Should reject private IPs
	assert.NotNil(t, f(&Decision{Value: "10.0.0.1"}))
	assert.NotNil(t, f(&Decision{Value: "192.168.1.1"}))
	assert.NotNil(t, f(&Decision{Value: "172.16.0.1"}))
	assert.NotNil(t, f(&Decision{Value: "127.0.0.1"}))
	assert.NotNil(t, f(&Decision{Value: "100.64.0.1"}))
	assert.NotNil(t, f(&Decision{Value: "::1"}))

	// Should allow public IPs
	assert.Nil(t, f(&Decision{Value: "8.8.8.8"}))
	assert.Nil(t, f(&Decision{Value: "203.0.113.42"}))
	assert.Nil(t, f(&Decision{Value: "2606:4700::1"}))
}

func TestMinDurationFilter(t *testing.T) {
	t.Run("disabled when zero", func(t *testing.T) {
		f := MinDurationFilter(0)
		assert.Nil(t, f(&Decision{Duration: "1s"}))
		assert.Nil(t, f(&Decision{Duration: "0s"}))
	})

	t.Run("rejects short durations", func(t *testing.T) {
		f := MinDurationFilter(5 * time.Minute)
		assert.NotNil(t, f(&Decision{Duration: "4m59s"}))
		assert.NotNil(t, f(&Decision{Duration: "60s"}))
		assert.Nil(t, f(&Decision{Duration: "5m"}))
		assert.Nil(t, f(&Decision{Duration: "1h"}))
		assert.Nil(t, f(&Decision{Duration: "72h30m15s"}))
	})
}

func TestParseGoDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"143h58m15s", 143*time.Hour + 58*time.Minute + 15*time.Second},
		{"3600s", 3600 * time.Second},
		{"24h", 24 * time.Hour},
		{"1h30m", 1*time.Hour + 30*time.Minute},
		{"0s", 0},
		{"72h", 72 * time.Hour},
		{"30m", 30 * time.Minute},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseGoDuration(tt.input))
		})
	}
}

func TestPipeline(t *testing.T) {
	filters := []Filter{
		ActionFilter("add"),
		OriginAllow("crowdsec", "cscli"),
		ScopeAllow("ip"),
		ValueRequired(),
		PrivateIPReject(),
	}

	t.Run("passes valid decision", func(t *testing.T) {
		d := &Decision{
			Action:   "add",
			Origin:   "crowdsec",
			Scope:    "Ip",
			Value:    "203.0.113.42",
			Scenario: "crowdsecurity/ssh-bf",
		}
		assert.Nil(t, Pipeline(filters, d))
	})

	t.Run("stops at first failure", func(t *testing.T) {
		d := &Decision{
			Action: "del",
			Origin: "crowdsec",
			Scope:  "Ip",
			Value:  "203.0.113.42",
		}
		reason := Pipeline(filters, d)
		assert.NotNil(t, reason)
		assert.Equal(t, "action", reason.Filter)
	})

	t.Run("rejects CAPI origin", func(t *testing.T) {
		d := &Decision{
			Action: "add",
			Origin: "CAPI",
			Scope:  "Ip",
			Value:  "203.0.113.42",
		}
		reason := Pipeline(filters, d)
		assert.NotNil(t, reason)
		assert.Equal(t, "origin", reason.Filter)
	})

	t.Run("rejects private IP", func(t *testing.T) {
		d := &Decision{
			Action: "add",
			Origin: "crowdsec",
			Scope:  "Ip",
			Value:  "192.168.1.1",
		}
		reason := Pipeline(filters, d)
		assert.NotNil(t, reason)
		assert.Equal(t, "private-ip", reason.Filter)
	})
}
