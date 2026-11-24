package unifi

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	ui "github.com/ubiquiti-community/go-unifi/unifi"
)

type firewallPolicyOrderingResource struct{ client *Client }

type firewallPolicyOrderingModel struct {
	Site        types.String `tfsdk:"site_id"`
	Source      types.String `tfsdk:"source_zone_id"`
	Destination types.String `tfsdk:"destination_zone_id"`
	Before      types.List   `tfsdk:"before_system_defined_policy_ids"`
	After       types.List   `tfsdk:"after_system_defined_policy_ids"`
}

var orderingUUID = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

func NewFirewallPolicyOrderingResource() resource.Resource { return &firewallPolicyOrderingResource{} }

func (r *firewallPolicyOrderingResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_policy_ordering"
}

func (r *firewallPolicyOrderingResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	uuid := stringvalidator.RegexMatches(orderingUUID, "must be a lowercase Integration API UUID")
	scope := func(desc string) schema.StringAttribute {
		return schema.StringAttribute{Required: true, MarkdownDescription: desc, Validators: []validator.String{uuid}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}
	}
	sequence := func(desc string) schema.ListAttribute {
		return schema.ListAttribute{Required: true, ElementType: types.StringType, MarkdownDescription: desc, Validators: []validator.List{listvalidator.UniqueValues(), listvalidator.ValueStringsAre(uuid)}}
	}
	resp.Schema = schema.Schema{MarkdownDescription: "Manage the complete order of user-defined firewall policies for one source/destination zone pair using the Integration API and an API key. Import the existing order first. Use Integration API UUIDs for policies and zones; legacy controller IDs from the firewall policy resource use a different namespace. Supply every current user policy exactly once across the two lists. Removing this resource releases ownership and leaves the controller order in place.", Attributes: map[string]schema.Attribute{
		"site_id":                          scope("Integration API site UUID."),
		"source_zone_id":                   scope("Source zone Integration API UUID."),
		"destination_zone_id":              scope("Destination zone Integration API UUID."),
		"before_system_defined_policy_ids": sequence("User policies evaluated before system-defined policies, in evaluation order."),
		"after_system_defined_policy_ids":  sequence("User policies evaluated after system-defined policies, in evaluation order."),
	}}
}

func (r *firewallPolicyOrderingResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	var ok bool
	r.client, ok = req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *Client, received %T.", req.ProviderData))
	}
}

func (r *firewallPolicyOrderingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m firewallPolicyOrderingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	order, err := r.client.GetFirewallPolicyOrder(ctx, ui.IntegrationSiteID(m.Site.ValueString()), m.Source.ValueString(), m.Destination.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not read firewall policy order", err.Error())
		return
	}
	var d diag.Diagnostics
	m.Before, d = types.ListValueFrom(ctx, types.StringType, order.Before)
	resp.Diagnostics.Append(d...)
	m.After, d = types.ListValueFrom(ctx, types.StringType, order.After)
	resp.Diagnostics.Append(d...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	}
}

func (r *firewallPolicyOrderingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.apply(ctx, req.Plan, &resp.State, &resp.Diagnostics)
}

func (r *firewallPolicyOrderingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.apply(ctx, req.Plan, &resp.State, &resp.Diagnostics)
}

func (r *firewallPolicyOrderingResource) apply(ctx context.Context, plan tfsdk.Plan, state *tfsdk.State, diags *diag.Diagnostics) {
	var m firewallPolicyOrderingModel
	diags.Append(plan.Get(ctx, &m)...)
	if diags.HasError() {
		return
	}
	want := ui.FirewallPolicyOrder{Before: []string{}, After: []string{}}
	diags.Append(m.Before.ElementsAs(ctx, &want.Before, false)...)
	diags.Append(m.After.ElementsAs(ctx, &want.After, false)...)
	if diags.HasError() {
		return
	}
	site, src, dst := ui.IntegrationSiteID(m.Site.ValueString()), m.Source.ValueString(), m.Destination.ValueString()
	current, err := r.client.GetFirewallPolicyOrder(ctx, site, src, dst)
	if err != nil {
		diags.AddError("Could not read current firewall policy order", err.Error())
		return
	}
	if err := checkOrderMembership(*current, want); err != nil {
		diags.AddError("Incomplete firewall policy order", err.Error())
		return
	}
	if !ordersEqual(*current, want) {
		result, err := r.client.SetFirewallPolicyOrder(ctx, site, src, dst, want)
		if err != nil {
			diags.AddError("Could not update firewall policy order", err.Error())
			return
		}
		if !ordersEqual(*result, want) {
			diags.AddError("Controller returned a different firewall policy order", "Refresh the resource and review this zone pair before applying again.")
			return
		}
	}
	diags.Append(state.Set(ctx, &m)...)
}

func ordersEqual(a, b ui.FirewallPolicyOrder) bool {
	return slices.Equal(a.Before, b.Before) && slices.Equal(a.After, b.After)
}

func checkOrderMembership(current, want ui.FirewallPolicyOrder) error {
	members := func(order ui.FirewallPolicyOrder) map[string]int {
		counts := make(map[string]int)
		for _, list := range [][]string{order.Before, order.After} {
			for _, id := range list {
				counts[id]++
			}
		}
		return counts
	}
	configured := members(want)
	for _, count := range configured {
		if count != 1 {
			return fmt.Errorf("each policy UUID must appear exactly once in the configured order")
		}
	}
	if !maps.Equal(members(current), configured) {
		return fmt.Errorf("the controller and configuration contain different policy IDs; inspect the current order and include every user policy for this zone pair")
	}
	return nil
}

// Ordering is a property of the zone pair. Removing Terraform ownership must preserve it.
func (r *firewallPolicyOrderingResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
}

func (r *firewallPolicyOrderingResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	if len(parts) != 3 || !orderingUUID.MatchString(parts[0]) || !orderingUUID.MatchString(parts[1]) || !orderingUUID.MatchString(parts[2]) {
		resp.Diagnostics.AddError("Invalid firewall order import ID", "Use <site-uuid>/<source-zone-uuid>/<destination-zone-uuid> from the Integration API.")
		return
	}
	m := firewallPolicyOrderingModel{Site: types.StringValue(parts[0]), Source: types.StringValue(parts[1]), Destination: types.StringValue(parts[2]), Before: types.ListNull(types.StringType), After: types.ListNull(types.StringType)}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
