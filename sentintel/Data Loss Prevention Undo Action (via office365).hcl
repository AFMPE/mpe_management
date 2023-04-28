resource "my_alert_rule" "rule_376" {
  name = "Data Loss Prevention Undo Action (via office365)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5H
  query_period = PT5H
  severity = Medium
  query = <<EOF
OfficeActivity 
| where (Operation == "DLPRuleUndo")
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = UserId
    }
  }
  tactics = ['DefenseEvasion']
  techniques = ['T1070']
  display_name = Data Loss Prevention Undo Action (via office365)
  description = <<EOT
Idicate a previously applied policy action has been \"undone\" – either because of false positive/override designation by user. Technique: T1078.
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
