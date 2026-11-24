package unifi

import (
	"context"
	"errors"
	"fmt"

	"github.com/ubiquiti-community/go-unifi/unifi"
)

// Several Terraform resource types share the controller's networkconf collection.
// The stable ID names the record, but only its remote purpose and VPN type identify
// which resource may manage it.
type managedNetworkKind string

const (
	lanNetwork       managedNetworkKind = "unifi_network"
	wanNetwork       managedNetworkKind = "unifi_wan"
	vpnClientNetwork managedNetworkKind = "unifi_vpn_client"
	vpnServerNetwork managedNetworkKind = "unifi_vpn_server"
	siteVPNNetwork   managedNetworkKind = "unifi_site_to_site_vpn"
)

func (kind managedNetworkKind) matches(n *unifi.Network) bool {
	vpnType := ""
	if n.VPNType != nil {
		vpnType = *n.VPNType
	}
	switch kind {
	case lanNetwork:
		return n.Purpose == unifi.PurposeCorporate || n.Purpose == unifi.PurposeGuest || n.Purpose == unifi.PurposeVLANOnly
	case wanNetwork:
		return n.Purpose == unifi.PurposeWAN
	case vpnClientNetwork:
		return n.Purpose == unifi.PurposeVPNClient && vpnType == "wireguard-client"
	case vpnServerNetwork:
		return n.Purpose == unifi.PurposeUserVPN &&
			(vpnType == "wireguard-server" || vpnType == "l2tp-server" || vpnType == "openvpn-server")
	case siteVPNNetwork:
		return n.Purpose == unifi.PurposeSiteVPN && vpnType == "ipsec-vpn"
	}
	return false
}

func (kind managedNetworkKind) validate(n *unifi.Network) error {
	if kind.matches(n) {
		return nil
	}
	vpnType := ""
	if n.VPNType != nil {
		vpnType = *n.VPNType
	}
	return fmt.Errorf("network %q has purpose %q and VPN type %q, which cannot be managed by %s; check the resource type and import ID", n.ID, n.Purpose, vpnType, kind)
}

func (c *Client) checkNetworkKind(ctx context.Context, site, id string, kind managedNetworkKind) error {
	if id == "" {
		return fmt.Errorf("%s requires a network ID before changing a controller record", kind)
	}
	n, err := c.GetNetwork(ctx, site, id)
	if err != nil {
		return err
	}
	return kind.validate(n)
}

func (c *Client) deleteManagedNetwork(ctx context.Context, site, id, name string, kind managedNetworkKind) error {
	if err := c.checkNetworkKind(ctx, site, id, kind); err != nil {
		var missing *unifi.NotFoundError
		if errors.As(err, &missing) {
			return nil
		}
		return err
	}
	return c.DeleteNetwork(ctx, site, id, name)
}
