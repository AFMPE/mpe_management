resource "my_alert_rule" "rule_38" {
  name = "Brute force attack against a Cloud PC"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let failureCountThreshold = 10;
let successCountThreshold = 1;
let authenticationWindow = 20m;
SigninLogs
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser, displayName =  tostring(DeviceDetail.displayName), deviceId = tostring(DeviceDetail.deviceId)
| extend
    StatusCode = tostring(Status.errorCode),
    StatusDetails = tostring(Status.additionalDetails)
| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city)
| where AppDisplayName =~ "Windows Sign In"
// Split out failure versus non-failure types
| extend FailureOrSuccess = iff(ResultType in ("0", "50125", "50140", "70043", "70044"), "Success", "Failure")
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), IPAddress = makeset(IPAddress), makeset(OS), makeset(Browser), makeset(City), makeset(displayName), makeset(deviceId),
    makeset(ResultType), FailureCount = countif(FailureOrSuccess == "Failure"), SuccessCount = countif(FailureOrSuccess == "Success") 
    by
    bin(TimeGenerated, authenticationWindow),
    UserDisplayName,
    UserPrincipalName,
    AppDisplayName
| where FailureCount >= failureCountThreshold and SuccessCount >= successCountThreshold
| mvexpand IPAddress
| extend IPAddress = tostring(IPAddress)
| extend
    timestamp = StartTime,
    AccountCustomEntity = UserPrincipalName,
    IPCustomEntity = IPAddress
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
  }
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = Brute force attack against a Cloud PC
  description = <<EOT
Identifies evidence of brute force activity against a Windows 365 Cloud PC by highlighting multiple authentication failures and by a successful authentication within a given time window.
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
