resource "my_alert_rule" "rule_380" {
  name = "Cisco Umbrella - URI contains IP address"
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
| where UrlOriginal matches regex @'\Ahttp:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*'
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
  tactics = ['CommandAndControl']
  techniques = ['T1071']
  display_name = Cisco Umbrella - URI contains IP address
  description = <<EOT
Malware can use IP address to communicate with C2.
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
