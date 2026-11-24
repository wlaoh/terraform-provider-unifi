package unifi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type cooldownRoundTripper func(*http.Request) (*http.Response, error)

func (f cooldownRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestConcurrentControllerReadsShareCooldown(t *testing.T) {
	newClient := func() *ApiClient {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !handleNewStyleSetup(w, r) {
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)
		client, err := New(t.Context(), &Config{BaseURL: srv.URL, APIKey: "test-key"})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	client, other := newClient(), newClient()

	synctest.Test(t, func(t *testing.T) {
		var attempts atomic.Int32
		client.c.HTTPClient.Transport = cooldownRoundTripper(func(req *http.Request) (*http.Response, error) {
			status := http.StatusNoContent
			h := make(http.Header)
			if req.Method == http.MethodGet && attempts.Add(1) == 1 {
				status = http.StatusTooManyRequests
				h.Set("Retry-After", "5")
			}
			return &http.Response{Request: req, Header: h, StatusCode: status, Body: http.NoBody}, nil
		})
		done := make(chan error, 2)
		go func() { done <- client.doRequest(t.Context(), http.MethodGet, "/query", nil, nil) }()
		synctest.Wait() // first request got a 429 and is waiting for its retry
		go func() { done <- client.doRequest(t.Context(), http.MethodGet, "/sibling", nil, nil) }()
		cancelled, cancel := context.WithCancel(t.Context())
		cancelDone := make(chan error, 1)
		go func() { cancelDone <- client.doRequest(cancelled, http.MethodGet, "/cancel", nil, nil) }()
		synctest.Wait()
		cancel()
		if err := <-cancelDone; !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled read: %v", err)
		}
		if n := attempts.Load(); n != 1 {
			t.Fatalf("%d attempts reached the controller during its cooldown", n)
		}
		start := time.Now()
		if err := client.doRequest(t.Context(), http.MethodPut, "/write", nil, nil); err != nil {
			t.Fatal(err)
		}
		if !time.Now().Equal(start) {
			t.Fatal("read cooldown delayed a mutation")
		}
		other.c.HTTPClient.Transport = cooldownRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{Request: req, StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
		})
		if err := other.doRequest(t.Context(), http.MethodGet, "/other", nil, nil); err != nil {
			t.Fatal(err)
		}
		if !time.Now().Equal(start) {
			t.Fatal("independent client waited for throttled controller")
		}
		// A late response to an in-flight request extends the window past the
		// first request's scheduled retry. Both outbound reads must recheck it.
		time.Sleep(3 * time.Second)
		client.readCooldown.extend(6 * time.Second)
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if n := attempts.Load(); n != 1 {
			t.Fatalf("overlapping throttle windows released an early read: %d attempts", n)
		}
		for range 2 {
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}
		if elapsed := time.Since(start); elapsed != 9*time.Second || attempts.Load() != 3 {
			t.Fatalf("reads finished after %v with %d attempts", elapsed, attempts.Load())
		}
	})
}

func TestReadCooldownDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, tc := range []struct {
			header string
			want   time.Duration
		}{
			{"5", 5 * time.Second},
			{"0", 0},
			{"", 4 * time.Second}, // exponential fallback on third attempt
			{"invalid", 4 * time.Second},
			{time.Now().Add(7 * time.Second).UTC().Format(http.TimeFormat), 7 * time.Second},
			{"3600", 30 * time.Second},
			{strings.Repeat("9", 32), 30 * time.Second},
		} {
			resp := &http.Response{Header: http.Header{"Retry-After": {tc.header}}}
			if got := readRetryDelay(time.Second, 30*time.Second, 2, resp); got != tc.want {
				t.Errorf("Retry-After %q: wanted %v, got %v", tc.header, tc.want, got)
			}
		}
	})
}
