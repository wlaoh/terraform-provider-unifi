package unifi

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/ubiquiti-community/go-unifi/unifi"
)

func TestManagedNetworkKinds(t *testing.T) {
	cases := []struct {
		purpose string
		vpnType string
		want    managedNetworkKind
	}{
		{unifi.PurposeCorporate, "", lanNetwork}, {unifi.PurposeVLANOnly, "", lanNetwork},
		{unifi.PurposeGuest, "", lanNetwork}, {unifi.PurposeWAN, "", wanNetwork},
		{unifi.PurposeVPNClient, "wireguard-client", vpnClientNetwork},
		{unifi.PurposeUserVPN, "wireguard-server", vpnServerNetwork},
		{unifi.PurposeUserVPN, "l2tp-server", vpnServerNetwork},
		{unifi.PurposeUserVPN, "openvpn-server", vpnServerNetwork},
		{unifi.PurposeSiteVPN, "ipsec-vpn", siteVPNNetwork},
		{unifi.PurposeSiteVPN, "openvpn-vpn", ""},
		{unifi.PurposeVPNClient, "openvpn-client", ""},
		{"", "", ""},
	}
	for _, tc := range cases {
		n := unifi.Network{ID: "network-id", Purpose: tc.purpose}
		if tc.vpnType != "" {
			n.VPNType = &tc.vpnType
		}
		for _, k := range []managedNetworkKind{lanNetwork, wanNetwork, vpnClientNetwork, vpnServerNetwork, siteVPNNetwork} {
			if valid := k.validate(&n) == nil; valid != (tc.want == k) {
				t.Errorf("%s/%s for %s: valid=%t", tc.purpose, tc.vpnType, k, valid)
			}
		}
	}
}

func TestForeignNetworkCannotBeAdoptedOrDestroyed(t *testing.T) {
	ctx := context.Background()
	// This fake answers GET only. A DELETE or PUT returns an ordinary HTTP error,
	// distinguishable from the provider's wrong-kind diagnostic.
	srv := newConfiguredProviderServer(t, newFakeController(t, map[string]string{
		"/api/s/default/rest/networkconf/lan": `{"meta":{"rc":"ok"},"data":[{"_id":"lan","name":"Existing LAN","purpose":"corporate"}]}`,
	}))
	schemas, err := srv.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []managedNetworkKind{wanNetwork, vpnClientNetwork, vpnServerNetwork, siteVPNNetwork} {
		t.Run(string(k), func(t *testing.T) {
			name := string(k)
			typ := schemas.ResourceSchemas[name].ValueType()
			state, err := tfprotov6.NewDynamicValue(typ, objectWithNulls(t, typ, map[string]tftypes.Value{
				"id": tftypes.NewValue(tftypes.String, "lan"), "site": tftypes.NewValue(tftypes.String, "default"),
			}))
			if err != nil {
				t.Fatal(err)
			}
			read, err := srv.ReadResource(ctx, &tfprotov6.ReadResourceRequest{TypeName: name, CurrentState: &state})
			if err != nil {
				t.Fatal(err)
			}
			expectMismatch := func(ds []*tfprotov6.Diagnostic) {
				t.Helper()
				for _, d := range ds {
					if d.Severity == tfprotov6.DiagnosticSeverityError && strings.Contains(d.Detail, "cannot be managed by "+name) {
						return
					}
				}
				t.Fatalf("expected a type mismatch for %s; diagnostics: %v", name, ds)
			}
			expectMismatch(read.Diagnostics)
			nullState, err := tfprotov6.NewDynamicValue(typ, tftypes.NewValue(typ, nil))
			if err != nil {
				t.Fatal(err)
			}
			del, err := srv.ApplyResourceChange(ctx, &tfprotov6.ApplyResourceChangeRequest{TypeName: name, PriorState: &state, PlannedState: &nullState, Config: &nullState})
			if err != nil {
				t.Fatal(err)
			}
			expectMismatch(del.Diagnostics)
		})
	}
}
