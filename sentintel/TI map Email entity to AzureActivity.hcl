resource "my_alert_rule" "rule_269" {
  name = "TI map Email entity to AzureActivity"
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
    AzureActivity | where TimeGenerated >= ago(dt_lookBack) and isnotempty(Caller)
    | extend Caller = tolower(Caller)
    | where Caller matches regex emailregex
    | extend AzureActivity_TimeGenerated = TimeGenerated
)
on $left.EmailSenderAddress == $right.Caller
| where AzureActivity_TimeGenerated < ExpirationDateTime
| summarize AzureActivity_TimeGenerated = arg_max(AzureActivity_TimeGenerated, *) by IndicatorId, Caller
| project AzureActivity_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, Url, EmailSenderName, EmailRecipient, 
EmailSourceDomain, EmailSourceIpAddress, EmailSubject, FileHashValue, FileHashType, Caller, Level, CallerIpAddress, CategoryValue, OperationNameValue, ActivityStatusValue, 
ResourceGroup, SubscriptionId
| extend timestamp = AzureActivity_TimeGenerated, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress, URLCustomEntity = Url
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
  display_name = TI map Email entity to AzureActivity
  description = <<EOT
Identifies a match in AzureActivity table from any Email IOC from TI
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
