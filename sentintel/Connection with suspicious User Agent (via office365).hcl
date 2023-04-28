resource "my_alert_rule" "rule_349" {
  name = "Connection with suspicious User Agent (via office365)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5H
  query_period = PT5H
  severity = Medium
  query = <<EOF
OfficeActivity 
| where (UserAgent contains "Wget" or UserAgent contains "curl" or UserAgent contains "PowerShell" or UserAgent contains "WinRM" or UserAgent contains "Bits")
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = UserId
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = ClientIP
    }
  }
  tactics = ['Discovery', 'CommandAndControl']
  techniques = ['T1082', 'T1219']
  display_name = Connection with suspicious User Agent (via office365)
  description = <<EOT
May be used for direct download via Powershell or other tools. Technique: T1105,T1105.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
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
