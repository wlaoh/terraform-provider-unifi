package unifi

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

func TestSettingTeleportImportAndUpdate(t *testing.T) {
	ctx := context.Background()
	r, puts := newSettingsFakeController(t, []map[string]any{{
		"key": "teleport", "enabled": true, "subnet_cidr": "192.0.2.0/24", "controller_only": "fixture",
	}})
	s := resourceSchema(t, r)
	resp := importSettings(ctx, t, r, true)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	var section types.Object
	if d := resp.State.GetAttribute(ctx, path.Root("teleport"), &section); d.HasError() {
		t.Fatal(d)
	}
	if len(section.Attributes()) != 1 || !types.BoolValue(true).Equal(section.Attributes()["enabled"]) {
		t.Fatalf("imported teleport = %v", section)
	}

	omitted := tfConfig(t, s, map[string]any{})
	plan := planResourceChange(t, "unifi_setting", s, resp.State.Raw, resp.State.Raw, omitted.Raw)
	if !resp.State.Raw.Equal(plan) {
		t.Fatal("omitting teleport changed the imported settings plan")
	}
	if got := puts(); len(got) != 0 {
		t.Fatalf("reads and planning wrote %v", got)
	}

	attrs := map[string]any{"id": "default", "site": "default", "teleport": map[string]any{"enabled": false}}
	update := &fwresource.UpdateResponse{State: resp.State, Identity: resp.Identity}
	r.Update(ctx, fwresource.UpdateRequest{State: resp.State, Plan: tfPlan(t, s, attrs), Config: tfConfig(t, s, attrs)}, update)
	if update.Diagnostics.HasError() {
		t.Fatal(update.Diagnostics)
	}
	want := map[string]map[string]any{"teleport": {"key": "teleport", "enabled": false}}
	if got := puts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("PUT = %v, want %v", got, want)
	}
	stored, err := r.storedSetting(ctx, "default", "teleport")
	if err != nil || stored["subnet_cidr"] != "192.0.2.0/24" || stored["controller_only"] != "fixture" {
		t.Fatalf("update lost controller fields: %v", err)
	}

	storedSettingSet(t, r, "teleport", "enabled", true)
	puts()
	read := &fwresource.ReadResponse{State: update.State, Identity: update.Identity}
	r.Read(ctx, fwresource.ReadRequest{State: update.State, Identity: update.Identity}, read)
	if read.Diagnostics.HasError() {
		t.Fatal(read.Diagnostics)
	}
	var enabled types.Bool
	if d := read.State.GetAttribute(ctx, path.Root("teleport").AtName("enabled"), &enabled); d.HasError() || !enabled.ValueBool() {
		t.Fatalf("refresh missed externally enabled Teleport: %v", d)
	}
	if got := puts(); len(got) != 0 {
		t.Fatalf("refresh wrote %v", got)
	}
}

func TestSettingTeleportAbsentOrOlderState(t *testing.T) {
	ctx := context.Background()
	r, puts := newSettingsFakeController(t, nil)
	resp := importSettings(ctx, t, r, false)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	var section types.Object
	if d := resp.State.GetAttribute(ctx, path.Root("teleport"), &section); d.HasError() || !section.IsNull() {
		t.Fatalf("absent Teleport document produced %v (%v)", section, d)
	}
	s := resp.State.Schema
	old := tfprotov6.RawState{JSON: []byte(`{"id":"default","site":"default"}`)}
	raw, err := old.Unmarshal(s.Type().TerraformType(ctx))
	if err != nil {
		t.Fatal(err)
	}
	prior := tfsdk.State{Raw: raw, Schema: s}
	read := &fwresource.ReadResponse{State: prior, Identity: resp.Identity}
	r.Read(ctx, fwresource.ReadRequest{State: prior, Identity: resp.Identity}, read)
	if read.Diagnostics.HasError() {
		t.Fatal(read.Diagnostics)
	}
	if d := read.State.GetAttribute(ctx, path.Root("teleport"), &section); d.HasError() || !section.IsNull() {
		t.Fatalf("old state acquired Teleport settings: %v (%v)", section, d)
	}
	if got := puts(); len(got) != 0 {
		t.Fatalf("import or upgrade wrote %v", got)
	}
}

func TestSettingTeleportCreatesDisabledDocument(t *testing.T) {
	r, puts := newSettingsFakeController(t, nil)
	resp := createSettings(t, r, map[string]any{"teleport": map[string]any{"enabled": false}})
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	want := map[string]map[string]any{"teleport": {"key": "teleport", "enabled": false}}
	if got := puts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("PUT = %v, want %v", got, want)
	}
}
