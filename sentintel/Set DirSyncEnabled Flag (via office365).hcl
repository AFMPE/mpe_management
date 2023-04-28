resource "my_alert_rule" "rule_126" {
  name = "Set DirSyncEnabled Flag (via office365)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5H
  query_period = PT5H
  severity = Medium
  query = <<EOF
OfficeActivity 
| where ((ResultStatus == "Success") and (ModifiedProperties contains "DirSyncEnabled"))
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = UserId
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = ClientIP
    }
  }
  tactics = ['Exfiltration']
  techniques = ['T1020']
  display_name = Set DirSyncEnabled Flag (via office365)
  description = <<EOT
Value of DirSyncEnabled attribute defines if its a cloud only account or synced account. Technique: T1020.
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
