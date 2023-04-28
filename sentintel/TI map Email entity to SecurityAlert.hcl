resource "my_alert_rule" "rule_342" {
  name = "TI map Email entity to SecurityAlert"
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
    SecurityAlert 
    | where TimeGenerated >= ago(dt_lookBack)
    | extend MSTI = case(AlertName has "TI map" and VendorName == "Microsoft" and ProductName == 'Azure Sentinel', true, false)
    | where MSTI == false
    // Converting Entities into dynamic data type and use mv-expand to unpack the array
    | extend EntitiesDynamicArray = parse_json(Entities) | mv-expand EntitiesDynamicArray
    // Parsing relevant entity column to filter type account and creating new column by combining account and UPNSuffix
    | extend Entitytype = tostring(parse_json(EntitiesDynamicArray).Type), EntityName = tostring(parse_json(EntitiesDynamicArray).Name),
    EntityUPNSuffix = tostring(parse_json(EntitiesDynamicArray).UPNSuffix)
    | where Entitytype =~ "account"
    | extend EntityEmail = tolower(strcat(EntityName, "@", EntityUPNSuffix))
    | where EntityEmail matches regex emailregex
    | extend Alert_TimeGenerated = TimeGenerated
)
on $left.EmailSenderAddress == $right.EntityEmail
| where Alert_TimeGenerated < ExpirationDateTime
| summarize Alert_TimeGenerated = arg_max(Alert_TimeGenerated, *) by IndicatorId, AlertName
| project Alert_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore, 
EmailSenderName, EmailRecipient, EmailSourceDomain, EmailSourceIpAddress, EmailSubject, FileHashValue, FileHashType, EntityEmail, AlertName, AlertType,
AlertSeverity, Entities, ProviderName, VendorName
| extend timestamp = Alert_TimeGenerated, AccountCustomEntity = EntityEmail, URLCustomEntity = Url
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = URLCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = None
  display_name = TI map Email entity to SecurityAlert
  description = <<EOT
Identifies a match in SecurityAlert table from any Email IOC from TI which will extend coverage to datatypes such as MCAS, StorageThreatProtection and many others
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
