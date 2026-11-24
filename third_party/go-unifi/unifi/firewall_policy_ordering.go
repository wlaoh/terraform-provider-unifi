package unifi

import (
	"context"
	"fmt"
	"net/http"
)

// FirewallPolicyOrder is the complete ordering of user policies for one zone pair.
type FirewallPolicyOrder struct {
	Before []string `json:"beforeSystemDefined"`
	After  []string `json:"afterSystemDefined"`
}

type firewallOrderEnvelope struct {
	Order *FirewallPolicyOrder `json:"orderedFirewallPolicyIds"`
}

func (c *ApiClient) GetFirewallPolicyOrder(ctx context.Context, site IntegrationSiteID, source, destination string) (*FirewallPolicyOrder, error) {
	return c.firewallPolicyOrder(ctx, http.MethodGet, site, source, destination, nil)
}

func (c *ApiClient) SetFirewallPolicyOrder(ctx context.Context, site IntegrationSiteID, source, destination string, order FirewallPolicyOrder) (*FirewallPolicyOrder, error) {
	return c.firewallPolicyOrder(ctx, http.MethodPut, site, source, destination, &firewallOrderEnvelope{Order: &order})
}

func (c *ApiClient) firewallPolicyOrder(ctx context.Context, method string, site IntegrationSiteID, source, destination string, body any) (*FirewallPolicyOrder, error) {
	if !integrationUUIDPattern.MatchString(string(site)) || !integrationUUIDPattern.MatchString(source) || !integrationUUIDPattern.MatchString(destination) {
		return nil, fmt.Errorf("firewall ordering requires Integration API site and zone UUIDs")
	}
	var response firewallOrderEnvelope
	err := c.do(ctx, method, fmt.Sprintf("integration/v1/sites/%s/firewall/policies/ordering", site), body, &response, map[string]string{
		"sourceFirewallZoneId": source, "destinationFirewallZoneId": destination,
	})
	if err != nil {
		return nil, err
	}
	if response.Order == nil || response.Order.Before == nil || response.Order.After == nil {
		return nil, fmt.Errorf("controller returned an incomplete firewall policy ordering")
	}
	return response.Order, nil
}
