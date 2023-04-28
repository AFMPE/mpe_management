resource "my_alert_rule" "rule_250" {
  name = "TI map IP entity to SigninLogs"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P14D
  severity = Medium
  query = <<EOF
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
let aadFunc = (tableName:string){
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| where Active == true
// Picking up only IOC's that contain the entities we want
| where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempty(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
// As there is potentially more than 1 indicator type for matching IP, taking NetworkIP first, then others if that is empty.
// Taking the first non-empty value based on potential IOC match availability
| extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinationIP)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP), NetworkSourceIP, TI_ipEntity)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAddress), EmailSourceIpAddress, TI_ipEntity)
// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated
| join kind=innerunique (
    table(tableName) | where TimeGenerated >= ago(dt_lookBack)
    | extend Status = todynamic(Status), LocationDetails = todynamic(LocationDetails)
    | extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails), StatusReason = tostring(Status.failureReason)
    | extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city), Region = tostring(LocationDetails.countryOrRegion)
    // renaming time column so it is clear the log this came from
    | extend SigninLogs_TimeGenerated = TimeGenerated, Type = Type
)
on $left.TI_ipEntity == $right.IPAddress
| where SigninLogs_TimeGenerated < ExpirationDateTime
| summarize SigninLogs_TimeGenerated = arg_max(SigninLogs_TimeGenerated, *) by IndicatorId, IPAddress
| project SigninLogs_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
TI_ipEntity, IPAddress, UserPrincipalName, AppDisplayName, StatusCode, StatusDetails, StatusReason, NetworkIP, NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress, Type
| extend timestamp = SigninLogs_TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress, URLCustomEntity = Url
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
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
  display_name = TI map IP entity to SigninLogs
  description = <<EOT
Identifies a match in SigninLogs from any IP IOC from TI
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
