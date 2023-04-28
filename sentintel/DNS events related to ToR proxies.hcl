resource "my_alert_rule" "rule_319" {
  name = "DNS events related to ToR proxies"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
DnsEvents
| where Name contains "."
| where Name has_any ("tor2web.org", "tor2web.com", "torlink.co", "onion.to", "onion.ink", "onion.cab", "onion.nu", "onion.link", 
"onion.it", "onion.city", "onion.direct", "onion.top", "onion.casa", "onion.plus", "onion.rip", "onion.dog", "tor2web.fi", 
"tor2web.blutmagie.de", "onion.sh", "onion.lu", "onion.pet", "t2w.pw", "tor2web.ae.org", "tor2web.io", "tor2web.xyz", "onion.lt", 
"s1.tor-gateways.de", "s2.tor-gateways.de", "s3.tor-gateways.de", "s4.tor-gateways.de", "s5.tor-gateways.de", "hiddenservice.net")
| extend timestamp = TimeGenerated, IPCustomEntity = ClientIP, HostCustomEntity = Computer
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['Exfiltration']
  techniques = ['T1048']
  display_name = DNS events related to ToR proxies
  description = <<EOT
Identifies IP addresses performing DNS lookups associated with common ToR proxies.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
