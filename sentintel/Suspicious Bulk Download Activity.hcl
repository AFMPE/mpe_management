resource "my_alert_rule" "rule_45" {
  name = "Suspicious Bulk Download Activity"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
AuditLogs 
| where (LoggedByService == "AAD Management UX" and Result == "success" and OperationName has "Download" and OperationName has "bulk")
| extend userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), ipAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend AccountCustomEntity = userPrincipalName
| project AccountCustomEntity, OperationName, ResultDescription, ipAddress
//Remove the second extend row and the project row to see full Azure Active Directory log. IP address has been parsed if there is one found in logs.
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
  }
  tactics = ['Exfiltration']
  techniques = ['T1041']
  display_name = Suspicious Bulk Download Activity
  description = <<EOT
'Detects Suspicious Bulk Download Activity'

EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
