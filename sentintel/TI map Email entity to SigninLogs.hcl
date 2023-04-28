resource "my_alert_rule" "rule_300" {
  name = "TI map Email entity to SigninLogs"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P14D
  severity = Medium
  query = <<EOF
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
let emailregex = @'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$';
let aadFunc = (tableName:string){
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| where Active == true
//Filtering the table for Email related IOCs
| where isnotempty(EmailSenderAddress)
// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated
| join kind=innerunique (
    table(tableName) | where TimeGenerated >= ago(dt_lookBack) and isnotempty(UserPrincipalName)
    //Normalizing the column to lower case for exact match with EmailSenderAddress column
    | extend UserPrincipalName = tolower(UserPrincipalName)
    | where UserPrincipalName matches regex emailregex
    | extend Status = todynamic(DeviceDetail), LocationDetails = todynamic(LocationDetails)
    | extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
    | extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city), Region = tostring(LocationDetails.countryOrRegion)
    // renaming timestamp column so it is clear the log this came from SigninLogs table
    | extend SigninLogs_TimeGenerated = TimeGenerated, Type = Type
)
on $left.EmailSenderAddress == $right.UserPrincipalName
| where SigninLogs_TimeGenerated < ExpirationDateTime
| summarize SigninLogs_TimeGenerated = arg_max(SigninLogs_TimeGenerated, *) by IndicatorId, UserPrincipalName
| project SigninLogs_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
EmailSenderName, EmailRecipient, EmailSourceDomain, EmailSourceIpAddress, EmailSubject, FileHashValue, FileHashType, IPAddress, UserPrincipalName, AppDisplayName,
StatusCode, StatusDetails, NetworkIP, NetworkDestinationIP, NetworkSourceIP, Type
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
  display_name = TI map Email entity to SigninLogs
  description = <<EOT
Identifies a match in SigninLogs table from any Email IOC from TI
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
