package unifi

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	ui "github.com/ubiquiti-community/go-unifi/unifi"
	"github.com/ubiquiti-community/terraform-provider-unifi/unifi/validators"
)

type icmpFirewallPolicyResource struct{ client *Client }

type icmpFirewallPolicyModel struct {
	ID                   types.String `tfsdk:"id"`
	Site                 types.String `tfsdk:"site_id"`
	Name                 types.String `tfsdk:"name"`
	Description          types.String `tfsdk:"description"`
	Action               types.String `tfsdk:"action"`
	Enabled              types.Bool   `tfsdk:"enabled"`
	AllowReturnTraffic   types.Bool   `tfsdk:"allow_return_traffic"`
	LoggingEnabled       types.Bool   `tfsdk:"logging_enabled"`
	SourceZone           types.String `tfsdk:"source_zone_id"`
	DestinationZone      types.String `tfsdk:"destination_zone_id"`
	SourceNetworks       types.Set    `tfsdk:"source_network_ids"`
	DestinationAddresses types.Set    `tfsdk:"destination_ipv4_addresses"`
}

func NewICMPFirewallPolicyResource() resource.Resource { return &icmpFirewallPolicyResource{} }

func (r *icmpFirewallPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_icmp_firewall_policy"
}

func (r *icmpFirewallPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	uuid := stringvalidator.RegexMatches(orderingUUID, "must be a lowercase Integration API UUID")
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage a user-defined IPv4 ICMP Echo Request firewall policy using an Integration API key. " +
			"Traffic must originate on one of the selected networks and target one of the listed IPv4 addresses within the configured zone pair. " +
			"Use Integration API UUIDs for all identifiers. " +
			"Each policy must have a single Terraform owner. " +
			"To adopt an existing policy, release any legacy `unifi_firewall_policy` state binding without destroying the policy, then import here. " +
			"Manage evaluation order separately with `unifi_firewall_policy_ordering`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Integration API policy UUID. Use this ID when managing zone-pair ordering.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"site_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Integration API site UUID.",
				Validators:          []validator.String{uuid},
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Policy name.",
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				MarkdownDescription: "Policy description.",
			},
			"action": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Action for matching echo requests. Select `ALLOW`, `BLOCK`, or `REJECT`.",
				Validators:          []validator.String{stringvalidator.OneOf("ALLOW", "BLOCK", "REJECT")},
			},
			"enabled": schema.BoolAttribute{
				Required:            true,
				MarkdownDescription: "Whether the policy is enabled.",
			},
			"allow_return_traffic": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "For an ALLOW policy, create a derived policy to allow return traffic. Defaults to false.",
			},
			"logging_enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Log traffic matching this policy. Defaults to false.",
			},
			"source_zone_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Integration API UUID of the source zone.",
				Validators:          []validator.String{uuid},
			},
			"destination_zone_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Integration API UUID of the destination zone. Select the gateway zone for traffic destined for the gateway itself.",
				Validators:          []validator.String{uuid},
			},
			"source_network_ids": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Integration API UUIDs of the source networks. Supply at least one.",
				Validators:          []validator.Set{setvalidator.SizeAtLeast(1), setvalidator.ValueStringsAre(uuid)},
			},
			"destination_ipv4_addresses": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Individual destination IPv4 addresses. Supply the gateway address to match ping requests to that gateway.",
				Validators:          []validator.Set{setvalidator.SizeAtLeast(1), setvalidator.ValueStringsAre(validators.IPv4Validator())},
			},
		},
	}
}

func (r *icmpFirewallPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	var ok bool
	r.client, ok = req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *Client, received %T.", req.ProviderData))
	}
}

func (r *icmpFirewallPolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m icmpFirewallPolicyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if !resp.Diagnostics.HasError() && !m.Action.IsUnknown() && !m.Action.IsNull() && m.AllowReturnTraffic.ValueBool() && m.Action.ValueString() != "ALLOW" {
		resp.Diagnostics.AddAttributeError(path.Root("allow_return_traffic"), "Return traffic requires ALLOW", "Use false for BLOCK or REJECT actions.")
	}
}

func (r *icmpFirewallPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	site, id, ok := strings.Cut(req.ID, "/")
	if !ok || !orderingUUID.MatchString(site) || !orderingUUID.MatchString(id) {
		resp.Diagnostics.AddError("Invalid ICMP policy import ID", "Use <site-uuid>/<policy-uuid> from the Integration API.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("site_id"), site)...)
}

func (m *icmpFirewallPolicyModel) store(ctx context.Context, p *ui.ICMPFirewallPolicy, state *tfsdk.State, diags *diag.Diagnostics) {
	m.ID, m.Name, m.Description = types.StringValue(p.ID), types.StringValue(p.Name), types.StringValue(p.Description)
	m.Action, m.Enabled = types.StringValue(p.Action), types.BoolValue(p.Enabled)
	m.AllowReturnTraffic, m.LoggingEnabled = types.BoolValue(p.AllowReturnTraffic), types.BoolValue(p.LoggingEnabled)
	m.SourceZone, m.DestinationZone = types.StringValue(p.SourceZoneID), types.StringValue(p.DestinationZoneID)
	var d diag.Diagnostics
	m.SourceNetworks, d = types.SetValueFrom(ctx, types.StringType, p.SourceNetworkIDs)
	diags.Append(d...)
	m.DestinationAddresses, d = types.SetValueFrom(ctx, types.StringType, p.DestinationIPv4Addresses)
	diags.Append(d...)
	if !diags.HasError() {
		diags.Append(state.Set(ctx, m)...)
	}
}

func (r *icmpFirewallPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m icmpFirewallPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.GetICMPFirewallPolicy(ctx, ui.IntegrationSiteID(m.Site.ValueString()), m.ID.ValueString())
	if errors.As(err, new(*ui.NotFoundError)) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Could not read ICMP firewall policy", err.Error())
		return
	}
	m.store(ctx, p, &resp.State, &resp.Diagnostics)
}

func (r *icmpFirewallPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.apply(ctx, req.Plan, &resp.State, &resp.Diagnostics, true)
}
func (r *icmpFirewallPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.apply(ctx, req.Plan, &resp.State, &resp.Diagnostics, false)
}

func (r *icmpFirewallPolicyResource) apply(ctx context.Context, plan tfsdk.Plan, state *tfsdk.State, diags *diag.Diagnostics, create bool) {
	var m icmpFirewallPolicyModel
	diags.Append(plan.Get(ctx, &m)...)
	if diags.HasError() {
		return
	}
	p := ui.ICMPFirewallPolicy{
		ID:                 m.ID.ValueString(),
		Name:               m.Name.ValueString(),
		Description:        m.Description.ValueString(),
		Action:             m.Action.ValueString(),
		Enabled:            m.Enabled.ValueBool(),
		LoggingEnabled:     m.LoggingEnabled.ValueBool(),
		AllowReturnTraffic: m.AllowReturnTraffic.ValueBool(),
		SourceZoneID:       m.SourceZone.ValueString(),
		DestinationZoneID:  m.DestinationZone.ValueString(),
	}
	diags.Append(m.SourceNetworks.ElementsAs(ctx, &p.SourceNetworkIDs, false)...)
	diags.Append(m.DestinationAddresses.ElementsAs(ctx, &p.DestinationIPv4Addresses, false)...)
	if diags.HasError() {
		return
	}
	site := ui.IntegrationSiteID(m.Site.ValueString())
	var result *ui.ICMPFirewallPolicy
	var err error
	if create {
		result, err = r.client.CreateICMPFirewallPolicy(ctx, site, p)
	} else {
		result, err = r.client.UpdateICMPFirewallPolicy(ctx, site, p)
	}
	r.client.firewallPolicies.Clear()
	if err != nil {
		if create && result != nil {
			// The POST succeeded. Keep its UUID so a subsequent run can locate the policy.
			m.ID = types.StringValue(result.ID)
			diags.Append(state.Set(ctx, &m)...)
		}
		diags.AddError("Could not apply ICMP firewall policy", err.Error())
		return
	}
	m.store(ctx, result, state, diags)
}

func (r *icmpFirewallPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m icmpFirewallPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.DeleteICMPFirewallPolicy(ctx, ui.IntegrationSiteID(m.Site.ValueString()), m.ID.ValueString())
	r.client.firewallPolicies.Clear()
	if err != nil && !errors.As(err, new(*ui.NotFoundError)) {
		resp.Diagnostics.AddError("Could not delete ICMP firewall policy", err.Error())
	}
}
