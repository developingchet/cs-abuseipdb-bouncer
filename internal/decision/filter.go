package decision

import (
	"fmt"
	"strings"
	"time"
)

// Decision represents a CrowdSec LAPI decision.
type Decision struct {
	ID       int64  `json:"id"`
	Action   string `json:"action"`
	Origin   string `json:"origin"`
	Scenario string `json:"scenario"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Type     string `json:"type"`
}

// SkipReason is returned by filters when a decision should be skipped.
type SkipReason struct {
	Filter string
	Detail string
}

func (s *SkipReason) Error() string {
	return fmt.Sprintf("%s: %s", s.Filter, s.Detail)
}

// Filter evaluates a decision and returns nil to pass or a SkipReason to reject.
type Filter func(d *Decision) *SkipReason

// Pipeline chains multiple filters. Returns the first SkipReason encountered, or nil if all pass.
func Pipeline(filters []Filter, d *Decision) *SkipReason {
	for _, f := range filters {
		if reason := f(d); reason != nil {
			return reason
		}
	}
	return nil
}

// ActionFilter passes only decisions with the specified action (typically "add").
func ActionFilter(allowed string) Filter {
	return func(d *Decision) *SkipReason {
		if d.Action != allowed {
			return &SkipReason{"action", fmt.Sprintf("action=%s (want %s)", d.Action, allowed)}
		}
		return nil
	}
}

// ScenarioExclude rejects decisions whose scenario contains any of the given substrings.
func ScenarioExclude(patterns ...string) Filter {
	return func(d *Decision) *SkipReason {
		lower := strings.ToLower(d.Scenario)
		for _, p := range patterns {
			if strings.Contains(lower, p) {
				return &SkipReason{"scenario-exclude", fmt.Sprintf("scenario=%s matches exclude pattern %q", d.Scenario, p)}
			}
		}
		return nil
	}
}

// OriginAllow passes only decisions with one of the listed origins.
func OriginAllow(allowed ...string) Filter {
	set := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		set[a] = true
	}
	return func(d *Decision) *SkipReason {
		if !set[d.Origin] {
			return &SkipReason{"origin", fmt.Sprintf("origin=%s not in allowed set", d.Origin)}
		}
		return nil
	}
}

// ScopeAllow passes only decisions with one of the listed scopes (case-insensitive).
func ScopeAllow(allowed ...string) Filter {
	set := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		set[strings.ToLower(a)] = true
	}
	return func(d *Decision) *SkipReason {
		if !set[strings.ToLower(d.Scope)] {
			return &SkipReason{"scope", fmt.Sprintf("scope=%s not in allowed set", d.Scope)}
		}
		return nil
	}
}

// ValueRequired rejects decisions with an empty value field.
func ValueRequired() Filter {
	return func(d *Decision) *SkipReason {
		if strings.TrimSpace(d.Value) == "" {
			return &SkipReason{"value", "empty value"}
		}
		return nil
	}
}

// PrivateIPReject rejects decisions targeting private or reserved IP ranges.
func PrivateIPReject() Filter {
	return func(d *Decision) *SkipReason {
		if IsPrivate(d.Value) {
			return &SkipReason{"private-ip", fmt.Sprintf("ip=%s is private/reserved", d.Value)}
		}
		return nil
	}
}

// MinDurationFilter rejects decisions shorter than the specified minimum duration.
// A minimum of zero disables the filter.
func MinDurationFilter(minimum time.Duration) Filter {
	return func(d *Decision) *SkipReason {
		if minimum <= 0 {
			return nil
		}
		dur := ParseGoDuration(d.Duration)
		if dur < minimum {
			return &SkipReason{"min-duration", fmt.Sprintf("duration=%s (%v) below minimum %v", d.Duration, dur, minimum)}
		}
		return nil
	}
}

// ParseGoDuration converts a Go-style duration string (e.g., "143h58m15s") to a
// time.Duration. Only handles h/m/s units (no nanoseconds or days).
func ParseGoDuration(s string) time.Duration {
	var total time.Duration
	var num int64

	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			num = num*10 + int64(c-'0')
		case c == 'h' || c == 'H':
			total += time.Duration(num) * time.Hour
			num = 0
		case c == 'm' || c == 'M':
			total += time.Duration(num) * time.Minute
			num = 0
		case c == 's' || c == 'S':
			total += time.Duration(num) * time.Second
			num = 0
		}
	}
	return total
}
