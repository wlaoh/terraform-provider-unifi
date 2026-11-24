package unifi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestFirewallPolicyOrderIntegrationContract(t *testing.T) {
	const site = "10000000-0000-0000-0000-000000000001"
	const source = "20000000-0000-0000-0000-000000000001"
	const destination = "20000000-0000-0000-0000-000000000002"
	order := FirewallPolicyOrder{Before: []string{}, After: []string{"30000000-0000-0000-0000-000000000001"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handleNewStyleSetup(w, r) {
			return
		}
		if r.URL.Path != "/proxy/network/integration/v1/sites/"+site+"/firewall/policies/ordering" ||
			r.URL.Query().Get("sourceFirewallZoneId") != source ||
			r.URL.Query().Get("destinationFirewallZoneId") != destination {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPut {
			var envelope firewallOrderEnvelope
			if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil || envelope.Order == nil {
				t.Errorf("invalid ordering body: %v", err)
				w.WriteHeader(400)
				return
			}
			order = *envelope.Order
		} else if r.Method != http.MethodGet {
			w.WriteHeader(405)
			return
		}
		if err := json.NewEncoder(w).Encode(firewallOrderEnvelope{Order: &order}); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	client, err := New(t.Context(), &Config{BaseURL: srv.URL, APIKey: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	read, err := client.GetFirewallPolicyOrder(t.Context(), site, source, destination)
	if err != nil || len(read.After) != 1 {
		t.Fatalf("initial order: %v, %v", read, err)
	}
	moved := FirewallPolicyOrder{Before: read.After, After: []string{}}
	got, err := client.SetFirewallPolicyOrder(t.Context(), site, source, destination, moved)
	if err != nil || !reflect.DeepEqual(got, &moved) {
		t.Fatalf("updated order: %v, %v", got, err)
	}
}
