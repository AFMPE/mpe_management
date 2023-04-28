resource "my_alert_rule" "rule_116" {
  name = "Security Event log cleared"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
(union isfuzzy=true
(
SecurityEvent
| where EventID == 1102 and EventSourceName == "Microsoft-Windows-Eventlog"
| extend Account = tostring(parse_xml(EventData).UserData.LogFileCleared.SubjectUserName)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), EventCount = count() by Computer, Account, EventID, Activity
| extend timestamp = StartTimeUtc, AccountCustomEntity = Account, HostCustomEntity = Computer
),
(
WindowsEvent
| where EventID == 1102 and Provider == "Microsoft-Windows-Eventlog"  
| extend Account =  strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend Activity= "1102 - The audit log was cleared."
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), EventCount = count() by Computer, Account, EventID, Activity
| extend timestamp = StartTimeUtc, AccountCustomEntity = Account, HostCustomEntity = Computer
)
)
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
  }
  tactics = ['DefenseEvasion']
  techniques = ['T1070']
  display_name = Security Event log cleared
  description = <<EOT
Checks for event id 1102 which indicates the security event log was cleared. 
It uses Event Source Name "Microsoft-Windows-Eventlog" to avoid generating false positives from other sources, like AD FS servers for instance.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = None
    group_by_custom_details = None
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
