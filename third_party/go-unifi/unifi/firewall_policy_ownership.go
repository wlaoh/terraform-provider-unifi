package unifi

import (
	"context"
	"fmt"
	"net/http"
)

// RequireCustomFirewallPolicy verifies current ownership before a mutation.
// Legacy controllers return the policy collection for an ID lookup. Decode the
// marker separately because FirewallPolicy.Predefined cannot distinguish a
// missing flag from an explicitly user-defined policy.
func (c *ApiClient) RequireCustomFirewallPolicy(ctx context.Context, site, id string) error {
	if id == "" {
		return fmt.Errorf("firewall policy ID is missing")
	}
	var policies []struct {
		ID         string `json:"_id"`
		Predefined *bool  `json:"predefined"`
	}
	path := fmt.Sprintf("v2/api/site/%s/firewall-policies", site)
	if err := c.do(ctx, http.MethodGet, path, nil, &policies); err != nil {
		return fmt.Errorf("could not verify firewall policy ownership: %w", err)
	}
	if policies == nil {
		return fmt.Errorf("controller returned an empty response when verifying firewall policy ownership")
	}
	for _, policy := range policies {
		if policy.ID == "" {
			return fmt.Errorf("controller returned a firewall policy without an ID")
		}
		if policy.ID != id {
			continue
		}
		if policy.Predefined == nil {
			return fmt.Errorf("controller did not report whether firewall policy %s is predefined", id)
		}
		if *policy.Predefined {
			return fmt.Errorf("UniFi owns predefined firewall policy %s; Terraform can import and read it, but cannot update or delete it", id)
		}
		return nil
	}
	return &NotFoundError{Type: "firewall policy", Attr: "_id", Value: id}
}
