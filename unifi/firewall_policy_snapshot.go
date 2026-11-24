package unifi

import (
	"context"
	"sync"
	"time"

	"github.com/ubiquiti-community/go-unifi/unifi"
)

// The SDK implements GetFirewallPolicy by listing the entire site. During a
// refresh, let different policy IDs consume one response instead. Limit the
// window for externally changed policies and always refetch when an ID is read
// again. A Terraform mutation discards the entire affected site's snapshot.
const firewallPolicySnapshotTTL = 2 * time.Second

type firewallPolicySnapshot struct {
	mu      sync.Mutex
	expires time.Time
	byID    map[string]*unifi.FirewallPolicy
}

type firewallPolicyCache struct {
	mu    sync.Mutex
	sites map[string]*firewallPolicySnapshot
}

func (c *firewallPolicyCache) site(name string) *firewallPolicySnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sites == nil {
		c.sites = make(map[string]*firewallPolicySnapshot)
	}
	if c.sites[name] == nil {
		c.sites[name] = &firewallPolicySnapshot{}
	}
	return c.sites[name]
}

func (c *firewallPolicyCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.sites)
}

func (c *Client) readFirewallPolicy(
	ctx context.Context,
	site, id string,
) (*unifi.FirewallPolicy, error) {
	snapshot := c.firewallPolicies.site(site)
	snapshot.mu.Lock()
	defer snapshot.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if policy := snapshot.byID[id]; policy != nil && time.Now().Before(snapshot.expires) {
		delete(snapshot.byID, id)
		return policy, nil
	}

	policies, err := c.ListFirewallPolicy(ctx, site)
	if err != nil {
		snapshot.byID = nil
		return nil, err
	}
	snapshot.expires = time.Now().Add(firewallPolicySnapshotTTL)
	snapshot.byID = make(map[string]*unifi.FirewallPolicy, len(policies))
	for i := range policies {
		snapshot.byID[policies[i].ID] = &policies[i]
	}
	policy := snapshot.byID[id]
	if policy == nil {
		return nil, &unifi.NotFoundError{}
	}
	delete(snapshot.byID, id)
	return policy, nil
}

func (c *Client) invalidateFirewallPolicies(site string) {
	c.firewallPolicies.mu.Lock()
	defer c.firewallPolicies.mu.Unlock()
	delete(c.firewallPolicies.sites, site)
}
