# Use Integration API UUIDs from this site. Replace these example values.
resource "unifi_icmp_firewall_policy" "gateway_ping" {
  site_id                    = "11111111-1111-4111-8111-111111111111"
  source_zone_id             = "22222222-2222-4222-8222-222222222222"
  destination_zone_id        = "33333333-3333-4333-8333-333333333333"
  source_network_ids         = ["44444444-4444-4444-8444-444444444444"]
  destination_ipv4_addresses = ["192.0.2.1"]
  name                       = "Allow ping to own gateway"
  action                     = "ALLOW"
  enabled                    = true
}
