resource "my_alert_rule" "rule_175" {
  name = "Reset User Password Operation (via office365)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5H
  query_period = PT5H
  severity = Medium
  query = <<EOF
OfficeActivity 
| where ((Operation == "Reset user password") and (ResultStatus == "Failure" or ResultStatus == "Success"))
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
  tactics = ['Persistence']
  techniques = ['T1098']
  display_name = Reset User Password Operation (via office365)
  description = <<EOT
Password reset action was performed. Technique: T1098.
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
