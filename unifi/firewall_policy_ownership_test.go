package unifi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	api "github.com/ubiquiti-community/go-unifi/unifi"
)

func TestFirewallPolicyMutationChecksCurrentOwnership(t *testing.T) {
	const policyID = "policy"
	const base = "/proxy/network/v2/api/site/default/firewall-policies"
	const custom = `{"_id":"policy","name":"Example","predefined":false,"action":"BLOCK"}`
	const predefined = `{"_id":"policy","name":"Example","predefined":true,"action":"BLOCK"}`
	for _, tc := range []struct {
		name         string
		list         string
		status       int
		updateFails  bool
		deleteFails  bool
		wantMutation bool
	}{
		{"custom", "[" + custom + "]", 200, false, false, true},
		{"predefined", "[" + predefined + "]", 200, true, true, false},
		{"missing ID", "[]", 200, true, false, false},
		{"unknown ownership", `[{"_id":"policy"}]`, 200, true, true, false},
		{"null ownership", `[{"_id":"policy","predefined":null}]`, 200, true, true, false},
		{"missing collection", "null", 200, true, true, false},
		{"unavailable endpoint", "{}", 404, true, true, false},
	} {
		for _, method := range []string{http.MethodPut, http.MethodDelete} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				var reads, writes int
				mux := http.NewServeMux()
				mux.HandleFunc(
					"GET /proxy/network/status",
					func(w http.ResponseWriter, _ *http.Request) {
						_, _ = io.WriteString(w, `{"meta":{"rc":"ok","server_version":"10.6.101"}}`)
					},
				)
				mux.HandleFunc("GET "+base, func(w http.ResponseWriter, _ *http.Request) {
					reads++
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.list)
				})
				mux.HandleFunc(
					method+" "+base+"/"+policyID,
					func(w http.ResponseWriter, _ *http.Request) {
						writes++
						if method == http.MethodPut {
							_, _ = io.WriteString(w, custom)
						}
					},
				)
				srv := httptest.NewServer(mux)
				t.Cleanup(srv.Close)
				ctx := t.Context()
				sdk, err := api.New(ctx, &api.Config{BaseURL: srv.URL, APIKey: "fixture"})
				if err != nil {
					t.Fatal(err)
				}
				r := &firewallPolicyResource{client: &Client{ApiClient: sdk, Site: "default"}}
				// A previous refresh claimed this ID was custom. Every mutation must
				// still inspect current controller ownership.
				snapshot := r.client.firewallPolicies.site("default")
				snapshot.expires = time.Now().Add(time.Hour)
				snapshot.byID = map[string]*api.FirewallPolicy{policyID: {
					ID: policyID, Name: "Example", Action: "BLOCK",
					Source:      &api.FirewallPolicySource{ZoneID: "source"},
					Destination: &api.FirewallPolicyDestination{ZoneID: "destination"},
				}}

				imported := newFirewallPolicyImportResponse(ctx, r)
				r.ImportState(ctx, resource.ImportStateRequest{ID: "default:" + policyID}, imported)
				if imported.Diagnostics.HasError() {
					t.Fatal(imported.Diagnostics)
				}
				input := resource.ReadRequest{State: imported.State, Identity: imported.Identity}
				read := resource.ReadResponse{State: imported.State, Identity: imported.Identity}
				r.Read(ctx, input, &read)
				if read.Diagnostics.HasError() {
					t.Fatal(read.Diagnostics)
				}
				snapshot.byID[policyID] = &api.FirewallPolicy{ID: policyID}
				if method == http.MethodPut {
					plan := tfsdk.Plan{Schema: read.State.Schema, Raw: read.State.Raw}
					resp := resource.UpdateResponse{State: read.State, Identity: read.Identity}
					r.Update(
						ctx,
						resource.UpdateRequest{
							Plan:     plan,
							State:    read.State,
							Identity: read.Identity,
						},
						&resp,
					)
					if resp.Diagnostics.HasError() != tc.updateFails {
						t.Fatalf("unexpected update result: %v", resp.Diagnostics)
					}
				} else {
					resp := resource.DeleteResponse{State: read.State}
					r.Delete(ctx, resource.DeleteRequest{State: read.State}, &resp)
					if resp.Diagnostics.HasError() != tc.deleteFails {
						t.Fatalf("unexpected delete result: %v", resp.Diagnostics)
					}
				}
				if reads != 1 || (writes == 1) != tc.wantMutation || writes > 1 {
					t.Fatalf("controller saw %d reads and %d writes", reads, writes)
				}
			})
		}
	}
}
