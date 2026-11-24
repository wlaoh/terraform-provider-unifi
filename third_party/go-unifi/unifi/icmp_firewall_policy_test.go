package unifi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const echoPolicyID = "50000000-0000-0000-0000-000000000001"
const echoSiteID = "10000000-0000-0000-0000-000000000001"

// Independently constructed example of the Integration API's "Firewall policy"
// schema and the specific discriminator branches this resource owns.
const echoResponse = `{
 "id":"50000000-0000-0000-0000-000000000001","index":2,"metadata":{"origin":"USER_DEFINED"},
 "name":"Gateway ping","enabled":true,"loggingEnabled":false,
 "action":{"type":"ALLOW","allowReturnTraffic":false},
 "source":{"zoneId":"20000000-0000-0000-0000-000000000001","trafficFilter":{"type":"NETWORK",
   "networkFilter":{"networkIds":["30000000-0000-0000-0000-000000000001"],"matchOpposite":false}}},
 "destination":{"zoneId":"20000000-0000-0000-0000-000000000002","trafficFilter":{"type":"IP_ADDRESS",
   "ipAddressFilter":{"type":"IP_ADDRESSES","matchOpposite":false,"items":[{"type":"IP_ADDRESS","value":"192.0.2.1"}]}}},
 "ipProtocolScope":{"ipVersion":"IPV4","protocolFilter":{"type":"NAMED_PROTOCOL","matchOpposite":false,
   "protocol":{"name":"icmp","typenameFilter":"ECHO_REQUEST"}}}
}`

func TestICMPFirewallPolicyRefusesUnsupportedShapes(t *testing.T) {
	for _, tc := range []struct{ name, before, after string }{
		{"built in", "USER_DEFINED", "SYSTEM_DEFINED"},
		{"derived", "USER_DEFINED", "DERIVED"},
		{"scheduled", `"index":2`, `"index":2,"schedule":{"mode":"EVERY_DAY"}`},
		{"connection state", `"index":2`, `"index":2,"connectionStateFilter":["NEW"]`},
		{"ipsec", `"index":2`, `"index":2,"ipsecFilter":"MATCH_ENCRYPTED"`},
		{"unknown nested action", `"type":"ALLOW"`, `"type":"ALLOW","futureFlag":true`},
		{"missing return flag", `,"allowReturnTraffic":false`, ``},
		{"source MAC", `"networkFilter":`, `"macAddressFilter":"02:00:00:00:00:01","networkFilter":`},
		{"destination port", `"ipAddressFilter":`, `"portFilter":{"type":"PORTS"},"ipAddressFilter":`},
		{"inverted networks", `],"matchOpposite":false`, `],"matchOpposite":true`},
		{"inverted addresses", `"matchOpposite":false,"items"`, `"matchOpposite":true,"items"`},
		{"missing positive", `"matchOpposite":false,"items"`, `"items"`},
		{"protocol excluded", `"NAMED_PROTOCOL","matchOpposite":false`, `"NAMED_PROTOCOL","matchOpposite":true`},
		{"other protocol", "ECHO_REQUEST", "ECHO_REPLY"},
		{"all ICMP types", `,"typenameFilter":"ECHO_REQUEST"`, ``},
		{"IPv6 scope", `"ipVersion":"IPV4"`, `"ipVersion":"IPV6"`},
		{"mixed address family", "192.0.2.1", "::ffff:192.0.2.1"},
		{"subnet item", `"type":"IP_ADDRESS","value"`, `"type":"SUBNET","value"`},
		{"empty source set", `["30000000-0000-0000-0000-000000000001"]`, `[]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(echoResponse, tc.before, tc.after, 1)
			if raw == echoResponse {
				t.Fatal("fixture was not changed")
			}
			if _, err := decodeICMPPolicy([]byte(raw), echoPolicyID); err == nil {
				t.Fatal("expected error for unsupported policy")
			}
		})
	}
	// The named protocol enum uses lowercase while the discriminator mapping uses uppercase.
	upper := strings.Replace(echoResponse, `"name":"icmp"`, `"name":"ICMP"`, 1)
	if _, err := decodeICMPPolicy([]byte(upper), echoPolicyID); err != nil {
		t.Fatal(err)
	}
	// The API documents null optional filters as unrestricted.
	raw := strings.Replace(echoResponse, `"index":2`, `"index":2,"connectionStateFilter":null,"schedule":null,"ipsecFilter":null`, 1)
	if _, err := decodeICMPPolicy([]byte(raw), echoPolicyID); err != nil {
		t.Fatal(err)
	}
}

func TestICMPFirewallPolicyIntegrationLifecycle(t *testing.T) {
	const collection = "/proxy/network/integration/v1/sites/" + echoSiteID + "/firewall/policies"
	var current map[string]any
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handleNewStyleSetup(w, r) {
			return
		}
		calls = append(calls, r.Method)
		path := collection + "/" + echoPolicyID
		if r.Method == http.MethodPost {
			path = collection
		}
		if r.URL.Path != path {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				return
			}
			var want map[string]any
			if err := json.Unmarshal([]byte(echoResponse), &want); err != nil {
				t.Error(err)
				return
			}
			for _, k := range []string{"id", "index", "metadata"} {
				delete(want, k)
			}
			if r.Method == http.MethodPut {
				want["name"] = "Disabled reject"
				want["enabled"] = false
				want["action"] = map[string]any{"type": "REJECT"}
			}
			if !reflect.DeepEqual(body, want) {
				t.Errorf("%s payload differs from official schema example: got %#v want %#v", r.Method, body, want)
			}
			current = body
			current["id"], current["index"], current["metadata"] = echoPolicyID, 2, map[string]any{"origin": "USER_DEFINED"}
			if r.Method == http.MethodPost {
				w.WriteHeader(201)
			}
		case http.MethodGet:
		case http.MethodDelete:
			w.WriteHeader(200)
			return
		default:
			t.Errorf("unexpected method %s", r.Method)
			return
		}
		if err := json.NewEncoder(w).Encode(current); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	client, err := New(t.Context(), &Config{BaseURL: srv.URL, APIKey: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := decodeICMPPolicy([]byte(echoResponse), echoPolicyID)
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CreateICMPFirewallPolicy(t.Context(), echoSiteID, *p)
	if err != nil || !reflect.DeepEqual(created, p) {
		t.Fatalf("create = %+v, %v", created, err)
	}
	currentPolicy, err := client.GetICMPFirewallPolicy(t.Context(), echoSiteID, echoPolicyID)
	if err != nil || !reflect.DeepEqual(currentPolicy, p) {
		t.Fatalf("get = %+v, %v", currentPolicy, err)
	}
	p.Name, p.Action, p.Enabled = "Disabled reject", "REJECT", false
	updated, err := client.UpdateICMPFirewallPolicy(t.Context(), echoSiteID, *p)
	if err != nil || !reflect.DeepEqual(updated, p) {
		t.Fatalf("update = %+v, %v", updated, err)
	}
	if err := client.DeleteICMPFirewallPolicy(t.Context(), echoSiteID, echoPolicyID); err != nil {
		t.Fatal(err)
	}
	if want := []string{"POST", "GET", "GET", "PUT", "GET", "DELETE"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("requests = %v", calls)
	}
}

func TestICMPFirewallPolicyGuardBeforeMutation(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handleNewStyleSetup(w, r) {
			return
		}
		calls = append(calls, r.Method)
		_, _ = io.WriteString(w, strings.Replace(echoResponse, "ECHO_REQUEST", "ECHO_REPLY", 1))
	}))
	defer srv.Close()
	client, err := New(t.Context(), &Config{BaseURL: srv.URL, APIKey: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := decodeICMPPolicy([]byte(echoResponse), echoPolicyID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.UpdateICMPFirewallPolicy(t.Context(), echoSiteID, *p); err == nil {
		t.Fatal("expected update to reject unsupported policy")
	}
	if err := client.DeleteICMPFirewallPolicy(t.Context(), echoSiteID, echoPolicyID); err == nil {
		t.Fatal("expected delete to reject unsupported policy")
	}
	if !reflect.DeepEqual(calls, []string{"GET", "GET"}) {
		t.Fatalf("requests = %v", calls)
	}
}
