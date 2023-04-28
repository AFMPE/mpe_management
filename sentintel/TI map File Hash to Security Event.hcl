resource "my_alert_rule" "rule_79" {
  name = "TI map File Hash to Security Event"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P14D
  severity = Medium
  query = <<EOF
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| where Active == true
| where isnotempty(FileHashValue)
| extend FileHashValue = toupper(FileHashValue)
// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated
| join kind=innerunique (
  SecurityEvent | where TimeGenerated >= ago(dt_lookBack)
      | where EventID in ("8003","8002","8005")
      | where isnotempty(FileHash)
      | extend SecurityEvent_TimeGenerated = TimeGenerated, Event = EventID, FileHash = toupper(FileHash)
)
on $left.FileHashValue == $right.FileHash
| where SecurityEvent_TimeGenerated < ExpirationDateTime
| summarize SecurityEvent_TimeGenerated = arg_max(SecurityEvent_TimeGenerated, *) by IndicatorId, FileHash
| project SecurityEvent_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
Process, FileHash, Computer, Account, Event
| extend timestamp = SecurityEvent_TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, URLCustomEntity = Url
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
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = URLCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = None
  display_name = TI map File Hash to Security Event
  description = <<EOT
Identifies a match in Security Event data from any File Hash IOC from TI
EOT
  enabled = False
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
