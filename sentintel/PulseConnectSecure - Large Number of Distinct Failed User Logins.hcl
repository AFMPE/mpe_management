resource "my_alert_rule" "rule_187" {
  name = "PulseConnectSecure - Large Number of Distinct Failed User Logins"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
let threshold = 100;
PulseConnectSecure
| where Messages startswith "Login failed"
| summarize dcount(User) by Computer, bin(TimeGenerated, 15m)
| where dcount_User > threshold
| extend timestamp = TimeGenerated, HostCustomEntity = Computer
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
  }
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = PulseConnectSecure - Large Number of Distinct Failed User Logins
  description = <<EOT
This query identifies evidence of failed login attempts from a large number of distinct users on a Pulse Connect Secure VPN server
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
