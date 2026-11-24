package unifi

import (
	"testing"

	ui "github.com/ubiquiti-community/go-unifi/unifi"
)

func TestFirewallOrderMembership(t *testing.T) {
	current := ui.FirewallPolicyOrder{Before: []string{"allow", "block"}, After: []string{"other"}}
	for _, tc := range []struct {
		name  string
		order ui.FirewallPolicyOrder
		valid bool
	}{
		{"no change", current, true},
		{"move across groups", ui.FirewallPolicyOrder{Before: []string{"block"}, After: []string{"allow", "other"}}, true},
		{"omitted policy", ui.FirewallPolicyOrder{Before: []string{"allow"}, After: []string{"other"}}, false},
		{"duplicate between groups", ui.FirewallPolicyOrder{Before: []string{"allow", "block"}, After: []string{"allow", "other"}}, false},
		{"policy from a different pair", ui.FirewallPolicyOrder{Before: []string{"unknown", "block"}, After: []string{"other"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkOrderMembership(current, tc.order); (err == nil) != tc.valid {
				t.Fatalf("validation error = %v, want valid %t", err, tc.valid)
			}
		})
	}
}
