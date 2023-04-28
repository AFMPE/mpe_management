resource "my_alert_rule" "rule_124" {
  name = "Secret Server - Suspicious Password Deletes"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
CommonSecurityLog
| where DeviceVendor == "Thycotic Software"
| where DeviceProduct == "Secret Server"
| where Activity == "SECRET - DELETE"
| where SourceUserName !has "conqueust_api"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), DeletedCount = count() by Activity, SourceUserName, SourceIP
| where DeletedCount >= 5 // threshold for alerting
| extend timestamp = StartTime
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = SourceUserName
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = SourceIP
    }
  }
  tactics = ['Impact']
  techniques = ['T1485']
  display_name = Secret Server - Suspicious Password Deletes
  description = <<EOT
This rule alerts when more then 5 passwords have been deleted in a 3 minute timeframe. 
EOT
  enabled = False
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
