package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubiquiti-community/go-unifi/unifi"
)

func TestFirewallPolicyRefreshSharesSiteCollection(t *testing.T) {
	const count = 16
	var requests atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("GET /proxy/network/status", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok","server_version":"10.6.101"}}`))
	})
	mux.HandleFunc(
		"GET /proxy/network/v2/api/site/{site}/firewall-policies",
		func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			policies := make([]unifi.FirewallPolicy, count)
			for i := range policies {
				policies[i].ID = strconv.Itoa(i)
				policies[i].Name = r.PathValue("site")
			}
			if err := json.NewEncoder(w).Encode(policies); err != nil {
				t.Error(err)
			}
		},
	)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	ctx := t.Context()
	api, err := unifi.New(ctx, &unifi.Config{BaseURL: server.URL, APIKey: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{ApiClient: api}

	read := func(site, id string) {
		t.Helper()
		policy, err := client.readFirewallPolicy(ctx, site, id)
		if err != nil || policy.ID != id || policy.Name != site {
			t.Errorf("read(%q, %q) returned %v, %v", site, id, policy, err)
		}
	}
	expectRequests := func(n int64) {
		t.Helper()
		if got := requests.Load(); got != n {
			t.Fatalf("expected %d collection reads, got %d", n, got)
		}
	}

	var wg sync.WaitGroup
	for i := range count {
		wg.Go(func() { read("first", strconv.Itoa(i)) })
	}
	wg.Wait()
	expectRequests(1)

	read("first", "0") // Repeated reads of one policy always get a fresh copy.
	read("second", "1")
	expectRequests(3)

	client.invalidateFirewallPolicies("first")
	read("first", "1")
	read("second", "2")
	expectRequests(4)

	entry := client.firewallPolicies.site("second")
	entry.expires = time.Now().Add(-time.Second)
	read("second", "3")
	expectRequests(5)

	_, err = client.readFirewallPolicy(ctx, "first", "missing")
	var missing *unifi.NotFoundError
	if !errors.As(err, &missing) {
		t.Fatalf("expected NotFoundError for a missing ID, got %v", err)
	}
	expectRequests(6)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := client.readFirewallPolicy(
		canceled,
		"first",
		"2",
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	expectRequests(6)
}
