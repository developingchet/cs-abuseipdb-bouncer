package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakePusher struct {
	mu       sync.Mutex
	payloads []MetricsPayload
	err      error
}

func (f *fakePusher) Push(_ context.Context, p MetricsPayload) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.payloads = append(f.payloads, p)
	return nil
}

func (f *fakePusher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.payloads)
}

func newHTTPPusher(url string) PushFunc {
	return func(ctx context.Context, p MetricsPayload) error {
		body, err := json.Marshal(p)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("push failed: http %d", resp.StatusCode)
		}
		return nil
	}
}

func TestPushFunc_PushDelegates(t *testing.T) {
	var called bool
	pf := PushFunc(func(ctx context.Context, payload MetricsPayload) error {
		called = true
		return nil
	})
	err := pf.Push(context.Background(), MetricsPayload{})
	require.NoError(t, err)
	assert.True(t, called)
}

func TestNewSender_Defaults(t *testing.T) {
	s := NewSender("v1.0.0", time.Unix(1, 0).UTC(), 0, nil, nil)
	assert.NotNil(t, s.counter)
	assert.Equal(t, 30*time.Minute, s.interval)
}

func TestSenderFlush_SuccessResetsCounter(t *testing.T) {
	counter := NewCounter()
	counter.AddProcessed(3)
	fp := &fakePusher{}

	s := NewSender("v2.0.0", time.Unix(1, 0).UTC(), 30*time.Minute, counter, fp)
	s.now = func() time.Time { return time.Unix(1800, 0).UTC() }

	err := s.Flush(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), counter.Processed())
	require.Equal(t, 1, fp.count())
}

func TestSenderFlush_ZeroProcessedDoesNothing(t *testing.T) {
	counter := NewCounter()
	fp := &fakePusher{}
	s := NewSender("v2.0.0", time.Unix(1, 0).UTC(), 30*time.Minute, counter, fp)

	err := s.Flush(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), counter.Processed())
	assert.Equal(t, 0, fp.count())
}

func TestSenderFlush_NilDependenciesNoop(t *testing.T) {
	require.NoError(t, (&Sender{}).Flush(context.Background()))
	require.NoError(t, (&Sender{counter: NewCounter()}).Flush(context.Background()))
	require.NoError(t, (&Sender{pusher: PushFunc(func(context.Context, MetricsPayload) error { return nil })}).Flush(context.Background()))
}

func TestSenderFlush_FailurePreservesCounter(t *testing.T) {
	counter := NewCounter()
	counter.AddProcessed(2)
	fp := &fakePusher{err: errors.New("boom")}

	s := NewSender("v2.0.0", time.Unix(1, 0).UTC(), 30*time.Minute, counter, fp)
	err := s.Flush(context.Background())
	require.Error(t, err)
	assert.Equal(t, int64(2), counter.Processed())
	assert.Equal(t, 0, fp.count())
}

func TestSenderRun_NoPusherEarlyReturn(t *testing.T) {
	s := NewSender("v2.0.0", time.Unix(1, 0).UTC(), 20*time.Millisecond, NewCounter(), nil)
	done := make(chan struct{})
	go func() {
		s.Run(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sender with nil pusher should return immediately")
	}
}

func TestSenderRun_StopsOnContextCancel(t *testing.T) {
	counter := NewCounter()
	counter.AddProcessed(1)
	fp := &fakePusher{}

	s := NewSender("v2.0.0", time.Unix(1, 0).UTC(), 20*time.Millisecond, counter, fp)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		s.Run(ctx)
		close(done)
	}()

	require.Eventually(t, func() bool { return fp.count() > 0 }, time.Second, 10*time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sender did not stop after context cancellation")
	}
}

func TestSenderFlush_HTTPPushSuccessResetsCounter(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/usage-metrics", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	counter := NewCounter()
	counter.AddProcessed(5)
	s := NewSender("v2.0.0", time.Unix(1, 0).UTC(), 30*time.Millisecond, counter, newHTTPPusher(srv.URL+"/v1/usage-metrics"))
	err := s.Flush(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), counter.Processed())
	assert.EqualValues(t, 1, calls.Load())
}

func TestSenderFlush_HTTPPushFailurePreservesCounter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	counter := NewCounter()
	counter.AddProcessed(5)
	s := NewSender("v2.0.0", time.Unix(1, 0).UTC(), 30*time.Millisecond, counter, newHTTPPusher(srv.URL+"/v1/usage-metrics"))
	err := s.Flush(context.Background())
	require.Error(t, err)
	assert.Equal(t, int64(5), counter.Processed())
}

func TestSenderRun_HTTPTickerPushesPeriodically(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	counter := NewCounter()
	counter.AddProcessed(1)
	s := NewSender("v2.0.0", time.Unix(1, 0).UTC(), 20*time.Millisecond, counter, newHTTPPusher(srv.URL))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		s.Run(ctx)
		close(done)
	}()

	require.Eventually(t, func() bool { return calls.Load() >= 1 }, time.Second, 10*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sender did not stop on cancel")
	}
}
