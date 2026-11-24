package unifi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	ui "github.com/ubiquiti-community/go-unifi/unifi"
)

func TestICMPFirewallPolicyResourceLifecycle(t *testing.T) {
	const id = "50000000-0000-0000-0000-000000000001"
	const site = "10000000-0000-0000-0000-000000000001"
	var current map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/":
			return
		case "/proxy/network/status":
			_, _ = io.WriteString(w, `{"meta":{"server_version":"10.0.0"}}`)
			return
		case "/proxy/network/integration/v1/sites/" + site + "/firewall/policies",
			"/proxy/network/integration/v1/sites/" + site + "/firewall/policies/" + id:
		default:
			t.Errorf("unexpected request %s", req.URL.Path)
			http.NotFound(w, req)
			return
		}
		switch req.Method {
		case http.MethodPost, http.MethodPut:
			var next map[string]any
			if err := json.NewDecoder(req.Body).Decode(&next); err != nil {
				t.Error(err)
				return
			}
			current = next
			current["id"], current["index"], current["metadata"] = id, 5, map[string]any{
				"origin": "USER_DEFINED",
			}
		case http.MethodDelete:
			current = nil
			return
		}
		if current == nil {
			http.NotFound(w, req)
			return
		}
		if err := json.NewEncoder(w).Encode(current); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	ctx := t.Context()
	client, err := ui.New(ctx, &ui.Config{BaseURL: srv.URL, APIKey: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	r := &icmpFirewallPolicyResource{client: &Client{ApiClient: client}}
	var s resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &s)
	empty := tfsdk.State{
		Schema: s.Schema,
		Raw:    tftypes.NewValue(s.Schema.Type().TerraformType(ctx), nil),
	}
	networks, d := types.SetValueFrom(
		ctx,
		types.StringType,
		[]string{"30000000-0000-0000-0000-000000000001", "30000000-0000-0000-0000-000000000002"},
	)
	if d.HasError() {
		t.Fatal(d)
	}
	addresses, d := types.SetValueFrom(ctx, types.StringType, []string{"192.0.2.1", "192.0.2.2"})
	if d.HasError() {
		t.Fatal(d)
	}
	model := icmpFirewallPolicyModel{
		ID:     types.StringUnknown(),
		Site:   types.StringValue(site),
		Name:   types.StringValue("Allow ping"),
		Action: types.StringValue("ALLOW"),
		Enabled: types.BoolValue(
			true,
		),
		Description:        types.StringValue("Gateway ICMP"),
		AllowReturnTraffic: types.BoolValue(true),
		LoggingEnabled:     types.BoolValue(false),
		SourceZone: types.StringValue(
			"20000000-0000-0000-0000-000000000001",
		),
		DestinationZone:      types.StringValue("20000000-0000-0000-0000-000000000002"),
		SourceNetworks:       networks,
		DestinationAddresses: addresses,
	}
	plan := tfsdk.Plan{Schema: s.Schema}
	if d := plan.Set(ctx, &model); d.HasError() {
		t.Fatal(d)
	}
	created := resource.CreateResponse{State: empty}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &created)
	if created.Diagnostics.HasError() {
		t.Fatal(created.Diagnostics)
	}
	imported := resource.ImportStateResponse{State: empty}
	r.ImportState(ctx, resource.ImportStateRequest{ID: site + "/" + id}, &imported)
	if imported.Diagnostics.HasError() {
		t.Fatal(imported.Diagnostics)
	}
	read := resource.ReadResponse{State: imported.State}
	r.Read(ctx, resource.ReadRequest{State: imported.State}, &read)
	if read.Diagnostics.HasError() {
		t.Fatal(read.Diagnostics)
	}
	if !read.State.Raw.Equal(created.State.Raw) {
		t.Fatal("import differs from created state")
	}
	if d := read.State.Get(ctx, &model); d.HasError() {
		t.Fatal(d)
	}
	if !model.ID.Equal(types.StringValue(id)) || !model.SourceNetworks.Equal(networks) ||
		!model.DestinationAddresses.Equal(addresses) ||
		!model.AllowReturnTraffic.ValueBool() {
		t.Fatalf("unexpected imported model %+v", model)
	}
	model.Action, model.AllowReturnTraffic, model.Enabled = types.StringValue(
		"BLOCK",
	), types.BoolValue(
		false,
	), types.BoolValue(
		false,
	)
	if d := plan.Set(ctx, &model); d.HasError() {
		t.Fatal(d)
	}
	updated := resource.UpdateResponse{State: read.State}
	r.Update(ctx, resource.UpdateRequest{State: read.State, Plan: plan}, &updated)
	if updated.Diagnostics.HasError() {
		t.Fatal(updated.Diagnostics)
	}
	if !updated.State.Raw.Equal(plan.Raw) {
		t.Fatal("update returned inconsistent state")
	}
	deleted := resource.DeleteResponse{State: updated.State}
	r.Delete(ctx, resource.DeleteRequest{State: updated.State}, &deleted)
	if deleted.Diagnostics.HasError() {
		t.Fatal(deleted.Diagnostics)
	}
	r.Read(ctx, resource.ReadRequest{State: updated.State}, &read)
	if read.Diagnostics.HasError() || !read.State.Raw.IsNull() {
		t.Fatalf("read after delete: %v", read.Diagnostics)
	}
	invalid := resource.ImportStateResponse{State: empty}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "default/" + id}, &invalid)
	if !invalid.Diagnostics.HasError() {
		t.Fatal("legacy site accepted")
	}
}
