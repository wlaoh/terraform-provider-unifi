package unifi

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	ui "github.com/ubiquiti-community/go-unifi/unifi"
	"github.com/ubiquiti-community/go-unifi/unifi/settings"
)

var teleportAttrTypes = map[string]attr.Type{"enabled": types.BoolType}

func teleportSchemaAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		MarkdownDescription: "Teleport remote-access VPN settings for this site.",
		Optional:            true,
		Computed:            true,
		PlanModifiers:       []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Enable Teleport remote-access VPN.",
				Required:            true,
			},
		},
	}
}

func (r *settingResource) persistTeleport(
	ctx context.Context, site string, config tfsdk.Config, diags *diag.Diagnostics,
) {
	if diags.HasError() {
		return
	}
	var section types.Object
	diags.Append(config.GetAttribute(ctx, path.Root("teleport"), &section)...)
	if diags.HasError() || !isKnown(section) {
		return
	}
	enabled := section.Attributes()["enabled"].(types.Bool)
	if !isKnown(enabled) {
		diags.AddError("Unknown Teleport setting", "teleport.enabled must be known when applying the configuration.")
		return
	}

	// The controller merges partial settings documents. Send just the switch so
	// that its assigned VPN subnet and any controller-only fields are preserved.
	err := r.client.UpdateSetting(ctx, site, &settings.RawSetting{
		BaseSetting: settings.BaseSetting{Key: "teleport"},
		Data:        map[string]any{"enabled": enabled.ValueBool()},
	})
	if err != nil {
		diags.AddError("Error Updating Teleport Setting", err.Error())
	}
}

func (r *settingResource) readTeleport(
	ctx context.Context, site string, data *settingResourceModel, diags *diag.Diagnostics,
) {
	if !isKnown(data.Teleport) {
		data.Teleport = types.ObjectNull(teleportAttrTypes)
		return
	}
	_, teleport, err := ui.GetSetting[*settings.Teleport](r.client.ApiClient, ctx, site)
	if err != nil {
		var missing *ui.NotFoundError
		if errors.As(err, &missing) {
			data.Teleport = types.ObjectNull(teleportAttrTypes)
			return
		}
		diags.AddError("Error Reading Teleport Setting", err.Error())
		return
	}
	section, diagnostics := types.ObjectValue(teleportAttrTypes, map[string]attr.Value{
		"enabled": types.BoolValue(teleport.Enabled),
	})
	diags.Append(diagnostics...)
	data.Teleport = section
}
