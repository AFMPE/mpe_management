resource "my_alert_rule" "rule_57" {
  name = "Multiple Teams deleted by a single user"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
// Adjust this value to change how many Teams should be deleted before including
let max_delete_count = 3;
// Adjust this value to change the timewindow the query runs over
  OfficeActivity
| where OfficeWorkload =~ "MicrosoftTeams" 
| where Operation =~ "TeamDeleted"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), DeletedTeams = make_set(TeamName) by UserId
| where array_length(DeletedTeams) > max_delete_count
| extend timestamp = StartTime, AccountCustomEntity = UserId
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = ['T1485', 'T1489']
  display_name = Multiple Teams deleted by a single user
  description = <<EOT
This detection flags the occurrences of deleting multiple teams within an hour.
This data is a part of Office 365 Connector in Azure Sentinel.
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
