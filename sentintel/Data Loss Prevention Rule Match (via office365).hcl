resource "my_alert_rule" "rule_23" {
  name = "Data Loss Prevention Rule Match (via office365)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5H
  query_period = PT5H
  severity = Medium
  query = <<EOF
OfficeActivity 
| where (Operation == "DLPRuleMatch")
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = UserId
    }
  }
  tactics = ['Exfiltration']
  techniques = ['T1041']
  display_name = Data Loss Prevention Rule Match (via office365)
  description = <<EOT
This indicates a rule was matched. These events exist in both Exchange and SharePoint Online and OneDrive for Business. Technique: T1114.
EOT
  enabled = False
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
