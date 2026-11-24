# Use the UUIDs returned by the Integration API for this site and zone pair.
resource "unifi_firewall_policy_ordering" "internal_gateway" {
  site_id             = var.integration_site_uuid
  source_zone_id      = var.internal_zone_uuid
  destination_zone_id = var.gateway_zone_uuid
  before_system_defined_policy_ids = [
    var.allow_iot_echo_policy_uuid,
    var.block_other_iot_gateway_policy_uuid,
  ]
  after_system_defined_policy_ids = []
}
