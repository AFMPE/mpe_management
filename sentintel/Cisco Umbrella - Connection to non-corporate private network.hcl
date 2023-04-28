resource "my_alert_rule" "rule_8" {
  name = "Cisco Umbrella - Connection to non-corporate private network"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT10M
  query_period = PT10M
  severity = Medium
  query = <<EOF
let lbtime = 10m;
Cisco_Umbrella
| where TimeGenerated > ago(lbtime)
| where EventType == 'proxylogs'
| where DvcAction =~ 'Allowed'
| where UrlCategory has_any ('Dynamic and Residential', 'Personal VPN')
| project TimeGenerated, SrcIpAddr, Identities
| extend IPCustomEntity = SrcIpAddr
| extend AccountCustomEntity = Identities
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['CommandAndControl', 'Exfiltration']
  techniques = ['T1571', 'T1011']
  display_name = Cisco Umbrella - Connection to non-corporate private network
  description = <<EOT
IP addresses of broadband links that usually indicates users attempting to access their home network, for example for a remote session to a home computer.
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
