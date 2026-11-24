package unifi

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestWireGuardPeerRefreshKeepsUnmanagedKeyOutOfState(t *testing.T) {
	ctx := context.Background()
	srv := newConfiguredProviderServer(t, newFakeController(t, map[string]string{
		"/v2/api/site/default/wireguard/network1/users": `[{"_id":"peer1","name":"fixture","network_id":"network1","interface_ip":"10.0.0.2","public_key":"synthetic","preshared_key":"synthetic-echo"}]`,
	}))
	schemas, err := srv.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	const name = "unifi_wireguard_peer"
	typ := schemas.ResourceSchemas[name].ValueType()
	state, err := tfprotov6.NewDynamicValue(typ, objectWithNulls(t, typ, map[string]tftypes.Value{
		"id":         tftypes.NewValue(tftypes.String, "peer1"),
		"network_id": tftypes.NewValue(tftypes.String, "network1"),
		"site":       tftypes.NewValue(tftypes.String, "default"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		read, err := srv.ReadResource(ctx, &tfprotov6.ReadResourceRequest{TypeName: name, CurrentState: &state})
		if err != nil {
			t.Fatal(err)
		}
		failOnErrorDiagnostics(t, "refresh", read.Diagnostics)
		state = *read.NewState
		val, err := state.Unmarshal(typ)
		if err != nil {
			t.Fatal(err)
		}
		var attrs map[string]tftypes.Value
		if err := val.As(&attrs); err != nil {
			t.Fatal(err)
		}
		if !attrs["preshared_key"].IsNull() || !attrs["preshared_key_wo"].IsNull() {
			t.Fatal("an unmanaged key entered persistent state")
		}
	}
}
