resource "my_alert_rule" "rule_237" {
  name = "TI map File Hash to CommonSecurityLog Event"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P14D
  severity = Medium
  query = <<EOF
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
let fileHashIndicators = ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| where Active == true
| where isnotempty(FileHashValue);
// Handle matches against both lower case and uppercase versions of the hash:
(fileHashIndicators | extend  FileHashValue = tolower(FileHashValue)
| union (fileHashIndicators | extend FileHashValue = toupper(FileHashValue)))
// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated
|  join kind=innerunique (
  CommonSecurityLog | where TimeGenerated >= ago(dt_lookBack)
  | where isnotempty(FileHash)
  | extend CommonSecurityLog_TimeGenerated = TimeGenerated
  )
on $left.FileHashValue == $right.FileHash
| where CommonSecurityLog_TimeGenerated < ExpirationDateTime
| summarize CommonSecurityLog_TimeGenerated = arg_max(CommonSecurityLog_TimeGenerated, *) by IndicatorId, FileHashValue
| project CommonSecurityLog_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
SourceIP, SourcePort, DestinationIP, DestinationPort, SourceUserID, SourceUserName, DeviceName, DeviceAction,
RequestURL, DestinationUserName, DestinationUserID, ApplicationProtocol, Activity
| extend timestamp = CommonSecurityLog_TimeGenerated, IPCustomEntity = SourceIP, HostCustomEntity = DeviceName, AccountCustomEntity = SourceUserName, URLCustomEntity = Url
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
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = URLCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = None
  display_name = TI map File Hash to CommonSecurityLog Event
  description = <<EOT
Identifies a match in CommonSecurityLog Event data from any FileHash IOC from TI
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
