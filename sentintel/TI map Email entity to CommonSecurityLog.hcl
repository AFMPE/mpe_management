resource "my_alert_rule" "rule_333" {
  name = "TI map Email entity to CommonSecurityLog"
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
    CommonSecurityLog | where TimeGenerated >= ago(dt_lookBack) and isnotempty(DestinationUserID)
    // Filtering PAN Logs for specific event type to match relevant email entities
    | where DeviceVendor == "Palo Alto Networks" and  DeviceEventClassID == "wildfire" and ApplicationProtocol in ("smtp","pop3")
    | extend DestinationUserID = tolower(DestinationUserID)
    | where DestinationUserID matches regex emailregex
    | extend CommonSecurityLog_TimeGenerated = TimeGenerated
)
on $left.EmailSenderAddress == $right.DestinationUserID
| where CommonSecurityLog_TimeGenerated < ExpirationDateTime
| summarize CommonSecurityLog_TimeGenerated = arg_max(CommonSecurityLog_TimeGenerated, *) by IndicatorId, DestinationUserID
| project CommonSecurityLog_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore, EmailSenderName, EmailRecipient, 
EmailSourceDomain, EmailSourceIpAddress, EmailSubject, FileHashValue, FileHashType, DestinationUserID, DeviceEventClassID, LogSeverity, DeviceAction, SourceIP, SourcePort, 
DestinationIP, DestinationPort, Protocol, ApplicationProtocol
| extend timestamp = CommonSecurityLog_TimeGenerated, AccountCustomEntity = DestinationUserID, IPCustomEntity = SourceIP, URLCustomEntity = Url
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
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = URLCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = None
  display_name = TI map Email entity to CommonSecurityLog
  description = <<EOT
Identifies a match in CommonSecurityLog table from any Email IOC from TI
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
