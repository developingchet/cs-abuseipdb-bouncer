package decision

import "testing"

func TestSkipReasonError(t *testing.T) {
	r := &SkipReason{Filter: "quota", Detail: "daily limit reached"}
	got := r.Error()
	want := "quota: daily limit reached"
	if got != want {
		t.Fatalf("unexpected error string: got %q want %q", got, want)
	}
}
