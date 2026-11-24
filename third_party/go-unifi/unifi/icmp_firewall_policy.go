package unifi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// ICMPFirewallPolicy matches IPv4 echo requests from networks to individual addresses.
// All IDs are Integration API UUIDs.
type ICMPFirewallPolicy struct {
	ID, Name, Description, Action               string
	Enabled, AllowReturnTraffic, LoggingEnabled bool
	SourceZoneID, DestinationZoneID             string
	SourceNetworkIDs, DestinationIPv4Addresses  []string
}

// The wire model is intentionally limited to one branch of each API discriminator.
// Explicitly null optional filters mean "unrestricted". Any configured filter that
// this resource cannot round-trip fails decoding before an update or delete.
type absentICMPFilter struct{}

func (*absentICMPFilter) UnmarshalJSON([]byte) error {
	return fmt.Errorf("policy has additional match criteria outside the supported IPv4 echo-request policy")
}

type icmpPolicyBody struct {
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	Enabled        *bool  `json:"enabled"`
	LoggingEnabled *bool  `json:"loggingEnabled"`
	Action         struct {
		Type               string `json:"type"`
		AllowReturnTraffic *bool  `json:"allowReturnTraffic,omitempty"`
	} `json:"action"`
	Source struct {
		ZoneID        string `json:"zoneId"`
		TrafficFilter struct {
			Type          string `json:"type"`
			NetworkFilter struct {
				NetworkIDs    []string `json:"networkIds"`
				MatchOpposite *bool    `json:"matchOpposite"`
			} `json:"networkFilter"`
			MACAddressFilter *absentICMPFilter `json:"macAddressFilter,omitempty"`
			PortFilter       *absentICMPFilter `json:"portFilter,omitempty"`
		} `json:"trafficFilter"`
	} `json:"source"`
	Destination struct {
		ZoneID        string `json:"zoneId"`
		TrafficFilter struct {
			Type            string `json:"type"`
			IPAddressFilter struct {
				Type          string            `json:"type"`
				MatchOpposite *bool             `json:"matchOpposite"`
				Items         []icmpAddressItem `json:"items"`
			} `json:"ipAddressFilter"`
			PortFilter *absentICMPFilter `json:"portFilter,omitempty"`
		} `json:"trafficFilter"`
	} `json:"destination"`
	IPProtocolScope struct {
		IPVersion      string `json:"ipVersion"`
		ProtocolFilter struct {
			Type          string `json:"type"`
			MatchOpposite *bool  `json:"matchOpposite"`
			Protocol      struct {
				Name           string `json:"name"`
				TypenameFilter string `json:"typenameFilter"`
			} `json:"protocol"`
		} `json:"protocolFilter"`
	} `json:"ipProtocolScope"`
	Schedule              *absentICMPFilter `json:"schedule,omitempty"`
	IPSecFilter           *absentICMPFilter `json:"ipsecFilter,omitempty"`
	ConnectionStateFilter *absentICMPFilter `json:"connectionStateFilter,omitempty"`
}

type icmpAddressItem struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (p ICMPFirewallPolicy) validate() error {
	if p.Name == "" || !integrationUUIDPattern.MatchString(p.SourceZoneID) || !integrationUUIDPattern.MatchString(p.DestinationZoneID) {
		return fmt.Errorf("an ICMP policy requires a name and source and destination zone UUIDs")
	}
	if (p.Action != "ALLOW" && p.Action != "BLOCK" && p.Action != "REJECT") || (p.Action != "ALLOW" && p.AllowReturnTraffic) {
		return fmt.Errorf("use ALLOW, BLOCK, or REJECT; only ALLOW supports return traffic")
	}
	if len(p.SourceNetworkIDs) == 0 || len(p.DestinationIPv4Addresses) == 0 {
		return fmt.Errorf("an ICMP policy requires at least one source network and one destination IPv4 address")
	}
	for _, id := range p.SourceNetworkIDs {
		if !integrationUUIDPattern.MatchString(id) {
			return fmt.Errorf("source network identifiers must be Integration API UUIDs")
		}
	}
	for _, ip := range p.DestinationIPv4Addresses {
		if addr, err := netip.ParseAddr(ip); err != nil || !addr.Is4() {
			return fmt.Errorf("destination addresses must be individual IPv4 addresses")
		}
	}
	return nil
}

func (p ICMPFirewallPolicy) body() *icmpPolicyBody {
	var b icmpPolicyBody
	opposite := false
	b.Name, b.Description, b.Enabled, b.LoggingEnabled = p.Name, p.Description, &p.Enabled, &p.LoggingEnabled
	b.Action.Type = p.Action
	if p.Action == "ALLOW" {
		b.Action.AllowReturnTraffic = &p.AllowReturnTraffic
	}
	b.Source.ZoneID = p.SourceZoneID
	source := &b.Source.TrafficFilter
	source.Type = "NETWORK"
	source.NetworkFilter.NetworkIDs, source.NetworkFilter.MatchOpposite = p.SourceNetworkIDs, &opposite
	b.Destination.ZoneID = p.DestinationZoneID
	dst := &b.Destination.TrafficFilter
	dst.Type = "IP_ADDRESS"
	dst.IPAddressFilter.Type, dst.IPAddressFilter.MatchOpposite = "IP_ADDRESSES", &opposite
	for _, ip := range p.DestinationIPv4Addresses {
		dst.IPAddressFilter.Items = append(dst.IPAddressFilter.Items, icmpAddressItem{Type: "IP_ADDRESS", Value: ip})
	}
	b.IPProtocolScope.IPVersion = "IPV4"
	protocol := &b.IPProtocolScope.ProtocolFilter
	protocol.Type, protocol.MatchOpposite = "NAMED_PROTOCOL", &opposite
	protocol.Protocol.Name, protocol.Protocol.TypenameFilter = "icmp", "ECHO_REQUEST"
	return &b
}

func decodeICMPPolicy(raw json.RawMessage, expectedID string) (*ICMPFirewallPolicy, error) {
	var identity struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &identity); err != nil || !integrationUUIDPattern.MatchString(identity.ID) || (expectedID != "" && identity.ID != expectedID) {
		return nil, fmt.Errorf("controller returned an invalid or unexpected policy UUID")
	}
	p := &ICMPFirewallPolicy{ID: identity.ID}
	var response struct {
		icmpPolicyBody
		ID       string `json:"id"`
		Index    int    `json:"index"`
		Metadata struct {
			Origin string `json:"origin"`
		} `json:"metadata"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return p, fmt.Errorf("controller returned a policy outside the supported schema: %w", err)
	}
	b := &response.icmpPolicyBody
	src, dst, protocol := b.Source.TrafficFilter, b.Destination.TrafficFilter, b.IPProtocolScope.ProtocolFilter
	if response.Metadata.Origin != "USER_DEFINED" || b.Enabled == nil || b.LoggingEnabled == nil ||
		src.Type != "NETWORK" || src.NetworkFilter.MatchOpposite == nil || *src.NetworkFilter.MatchOpposite ||
		dst.Type != "IP_ADDRESS" || dst.IPAddressFilter.Type != "IP_ADDRESSES" || dst.IPAddressFilter.MatchOpposite == nil || *dst.IPAddressFilter.MatchOpposite ||
		b.IPProtocolScope.IPVersion != "IPV4" || protocol.Type != "NAMED_PROTOCOL" || protocol.MatchOpposite == nil || *protocol.MatchOpposite ||
		!strings.EqualFold(protocol.Protocol.Name, "icmp") || protocol.Protocol.TypenameFilter != "ECHO_REQUEST" ||
		(b.Action.Type == "ALLOW") != (b.Action.AllowReturnTraffic != nil) {
		return p, fmt.Errorf("expected a user-defined IPv4 ECHO_REQUEST policy with positive network and address matches and a supported action")
	}
	p.Name, p.Description, p.Enabled, p.LoggingEnabled = b.Name, b.Description, *b.Enabled, *b.LoggingEnabled
	p.Action, p.AllowReturnTraffic = b.Action.Type, b.Action.AllowReturnTraffic != nil && *b.Action.AllowReturnTraffic
	p.SourceZoneID, p.DestinationZoneID = b.Source.ZoneID, b.Destination.ZoneID
	p.SourceNetworkIDs = src.NetworkFilter.NetworkIDs
	for _, item := range dst.IPAddressFilter.Items {
		if item.Type != "IP_ADDRESS" {
			return p, fmt.Errorf("expected only individual IP_ADDRESS destination items")
		}
		p.DestinationIPv4Addresses = append(p.DestinationIPv4Addresses, item.Value)
	}
	return p, p.validate()
}

func (c *ApiClient) icmpPolicyRequest(ctx context.Context, method string, site IntegrationSiteID, id string, p *ICMPFirewallPolicy) (*ICMPFirewallPolicy, error) {
	if c.apiKey == "" || !integrationUUIDPattern.MatchString(string(site)) {
		return nil, fmt.Errorf("ICMP firewall policies require an API key and an Integration API site UUID")
	}
	endpoint := fmt.Sprintf("integration/v1/sites/%s/firewall/policies", site)
	if method != http.MethodPost {
		if !integrationUUIDPattern.MatchString(id) {
			return nil, fmt.Errorf("expected an Integration API firewall policy UUID")
		}
		endpoint += "/" + id
	}
	var body any
	if p != nil {
		if err := p.validate(); err != nil {
			return nil, err
		}
		body = p.body()
	}
	if method == http.MethodDelete {
		return nil, c.do(ctx, method, endpoint, nil, nil)
	}
	var raw json.RawMessage
	if err := c.do(ctx, method, endpoint, body, &raw); err != nil {
		return nil, err
	}
	return decodeICMPPolicy(raw, id)
}

func (c *ApiClient) GetICMPFirewallPolicy(ctx context.Context, site IntegrationSiteID, id string) (*ICMPFirewallPolicy, error) {
	return c.icmpPolicyRequest(ctx, http.MethodGet, site, id, nil)
}

func (c *ApiClient) CreateICMPFirewallPolicy(ctx context.Context, site IntegrationSiteID, p ICMPFirewallPolicy) (*ICMPFirewallPolicy, error) {
	return c.icmpPolicyRequest(ctx, http.MethodPost, site, "", &p)
}

func (c *ApiClient) UpdateICMPFirewallPolicy(ctx context.Context, site IntegrationSiteID, p ICMPFirewallPolicy) (*ICMPFirewallPolicy, error) {
	if _, err := c.GetICMPFirewallPolicy(ctx, site, p.ID); err != nil {
		return nil, err
	}
	return c.icmpPolicyRequest(ctx, http.MethodPut, site, p.ID, &p)
}

func (c *ApiClient) DeleteICMPFirewallPolicy(ctx context.Context, site IntegrationSiteID, id string) error {
	if _, err := c.GetICMPFirewallPolicy(ctx, site, id); err != nil {
		return err
	}
	_, err := c.icmpPolicyRequest(ctx, http.MethodDelete, site, id, nil)
	return err
}
