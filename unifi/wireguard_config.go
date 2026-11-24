package unifi

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// wireguardConfigParsed contains the parsed fields from a WireGuard .conf file.
type wireguardConfigParsed struct {
	// Interface section
	PrivateKey string
	Address    string
	DNS        []string

	// Peer section
	PublicKey    string
	Endpoint     string
	EndpointIP   string
	EndpointPort int64
	AllowedIPs   string
	PresharedKey string
}

// parseWireGuardConfig parses a standard WireGuard configuration file content
// and extracts the relevant fields.
func parseWireGuardConfig(content string) (*wireguardConfigParsed, error) {
	result := &wireguardConfigParsed{}
	var section string
	seenPeer := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		text, _, _ := strings.Cut(scanner.Text(), "#")
		line := strings.TrimSpace(text)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			if section == "peer" {
				if seenPeer {
					return nil, fmt.Errorf("UniFi VPN clients support exactly one WireGuard peer")
				}
				seenPeer = true
			}
			continue
		}

		// Parse key = value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch section {
		case "interface":
			switch strings.ToLower(key) {
			case "privatekey":
				result.PrivateKey = value
			case "address":
				result.Address = value
			case "dns":
				for _, dns := range strings.Split(value, ",") {
					dns = strings.TrimSpace(dns)
					if dns != "" {
						result.DNS = append(result.DNS, dns)
					}
				}
			}
		case "peer":
			switch strings.ToLower(key) {
			case "publickey":
				result.PublicKey = value
			case "endpoint":
				result.Endpoint = value
				host, port, err := parseEndpoint(value)
				if err != nil {
					return nil, err
				}
				result.EndpointIP = host
				result.EndpointPort = port
			case "allowedips":
				if value == "" {
					return nil, fmt.Errorf("WireGuard AllowedIPs cannot be empty")
				}
				result.AllowedIPs = value
			case "presharedkey":
				result.PresharedKey = value
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading WireGuard configuration: %w", err)
	}

	if result.PublicKey == "" {
		return nil, fmt.Errorf("WireGuard configuration missing [Peer] PublicKey")
	}

	if result.Endpoint == "" {
		return nil, fmt.Errorf("WireGuard configuration missing [Peer] Endpoint")
	}

	return result, nil
}

var wireguardEndpointHostname = regexp.MustCompile(`(?i)^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.?$`)

func parseEndpoint(endpoint string) (string, int64, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return "", 0, fmt.Errorf("WireGuard Endpoint must be a host and port; enclose IPv6 addresses in brackets")
	}
	if _, err := netip.ParseAddr(host); err != nil && (len(host) > 253 || !wireguardEndpointHostname.MatchString(host)) {
		return "", 0, fmt.Errorf("WireGuard Endpoint must have a valid IP address or DNS hostname")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("WireGuard Endpoint port must be an integer from 1 to 65535")
	}
	return host, int64(port), nil
}

// UniFi's manual WireGuard client endpoint has no peer selector field.
func parseUniFiWireGuardFile(content string) (*wireguardConfigParsed, error) {
	config, err := parseWireGuardBase64Config(content)
	if err != nil {
		return nil, err
	}
	if config.AllowedIPs != "" {
		return nil, fmt.Errorf("the UniFi manual VPN client API cannot preserve WireGuard AllowedIPs; use a method that enforces your peer selectors before omitting this directive")
	}
	return config, nil
}

type wireguardFileValidator struct{}

func (wireguardFileValidator) Description(context.Context) string {
	return "Requires a base64-encoded single-peer WireGuard configuration supported by the UniFi client."
}

func (v wireguardFileValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (wireguardFileValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, err := parseUniFiWireGuardFile(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid WireGuard Configuration File", err.Error())
	}
}

// parseWireGuardBase64Config decodes and parses a base64-encoded WireGuard config.
func parseWireGuardBase64Config(b64Content string) (*wireguardConfigParsed, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64Content)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding: %w", err)
	}

	return parseWireGuardConfig(string(decoded))
}

// ipv6FromAddress returns the first IPv6 prefix of a WireGuard `Address` value
// (e.g. "10.0.0.2/30, 2001:db8::2/64" -> "2001:db8::2/64"), or "" if it has none.
func ipv6FromAddress(address string) string {
	for _, a := range strings.Split(address, ",") {
		a = strings.TrimSpace(a)
		if prefix, err := netip.ParsePrefix(a); err == nil && prefix.Addr().Is6() &&
			!prefix.Addr().Is4In6() {
			return a
		}
	}
	return ""
}
