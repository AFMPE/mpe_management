resource "my_alert_rule" "rule_378" {
  name = "TI map Email entity to SecurityEvent"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P14D
  severity = Medium
  query = <<EOF
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
let emailregex = @'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$';
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| where Active == true
//Filtering the table for Email related IOCs
| where isnotempty(EmailSenderAddress)
// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated
| join kind=innerunique ( 
(union isfuzzy=true
(SecurityEvent
| where TimeGenerated >= ago(dt_lookBack) and isnotempty(TargetUserName)
//Normalizing the column to lower case for exact match with EmailSenderAddress column
| extend TargetUserName = tolower(TargetUserName)
// renaming timestamp column so it is clear the log this came from SecurityEvent table
| extend SecurityEvent_TimeGenerated = TimeGenerated
),
(WindowsEvent
| where TimeGenerated >= ago(dt_lookBack) 
| extend TargetUserName = tostring(EventData.TargetUserName) 
| where isnotempty(TargetUserName)
//Normalizing the column to lower case for exact match with EmailSenderAddress column
| extend TargetUserName = tolower(TargetUserName)
// renaming timestamp column so it is clear the log this came from SecurityEvent table
| extend SecurityEvent_TimeGenerated = TimeGenerated
))
)
on $left.EmailSenderAddress == $right.TargetUserName
| where SecurityEvent_TimeGenerated < ExpirationDateTime
| summarize SecurityEvent_TimeGenerated = arg_max(SecurityEvent_TimeGenerated, *) by IndicatorId, TargetUserName
| project SecurityEvent_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
EmailSenderName, EmailRecipient, EmailSourceDomain, EmailSourceIpAddress, EmailSubject, FileHashValue, FileHashType, Computer, EventID, TargetUserName, Activity, IpAddress, AccountType,
LogonTypeName, LogonProcessName, Status, SubStatus
| extend
timestamp = SecurityEvent_TimeGenerated,
AccountCustomEntity = TargetUserName,
IPCustomEntity = IpAddress,
HostCustomEntity = Computer,
URLCustomEntity = Url
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
  display_name = TI map Email entity to SecurityEvent
  description = <<EOT
Identifies a match in SecurityEvent table from any Email IOC from TI
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
