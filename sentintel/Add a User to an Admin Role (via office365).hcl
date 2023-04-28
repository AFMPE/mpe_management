resource "my_alert_rule" "rule_1" {
  name = "Add a User to an Admin Role (via office365)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
OfficeActivity 
| where ((ModifiedProperties contains "admin") and (Operation == "Add member to role") and (ResultStatus == "Success"))
| extend AccountCustomEntity = UserId
| extend IPCustomEntity = ClientIP
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
  tactics = ['Persistence']
  techniques = ['T1098']
  display_name = Add a User to an Admin Role (via office365)
  description = <<EOT
Added a user to an admin role in Office 365. Technique: T1098.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = PT5M
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = None
    group_by_custom_details = None
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
