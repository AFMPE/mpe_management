resource "my_alert_rule" "rule_311" {
  name = "Multiple Login Failures followed by Success in Azure"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
let timeframe = 1h;
let threshold = 10;
let allSignIns = materialize (SigninLogs | where TimeGenerated >= ago(timeframe));
let failedOfficeSignIns = allSignIns | where TimeGenerated >= ago(timeframe) | where ResultType !in ("0", "50125", "50140");
failedOfficeSignIns
| summarize TimeGenerated = makelist(TimeGenerated), Status = makelist(Status), IPAddresses = makelist(IPAddress), IPAddressCount = dcount(IPAddress), FailedLogonCount = count() by UserPrincipalName, UserId, UserDisplayName, AppDisplayName
| extend StartTime = bin(todatetime(parse_json(TimeGenerated)[0]), 1m)
| where FailedLogonCount >= threshold
| mv-expand IPAddresses
| project TimeGenerated, StartTime, UserPrincipalName, UserId, UserDisplayName, AppDisplayName, Status, tostring(IPAddresses), IPAddressCount, FailedLogonCount
| extend UPN = tolower(UserPrincipalName)
| join kind=inner (
    SigninLogs
    | where ConditionalAccessStatus has "success"
    | extend AuthDetails = todynamic(AuthenticationDetails)
    | mv-expand AuthDetails
    | extend LoginSuccess = parse_json(AuthDetails).succeeded
    | where LoginSuccess has "true"
    | project SuccessfulLoginTime = TimeGenerated, IPAddress, UserPrincipalName
    ) on $left.IPAddresses == $right.IPAddress and $left.UPN == $right.UserPrincipalName
| where SuccessfulLoginTime >= StartTime
| summarize makeset(AppDisplayName), makeset(SuccessfulLoginTime) by IPAddress, UPN, FailedLogonCount
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = UPN
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPAddress
    }
  }
  tactics = ['InitialAccess', 'CredentialAccess']
  techniques = ['T1110']
  display_name = Multiple Login Failures followed by Success in Azure
  description = <<EOT
This rule finds any instances where the same user has failed to login 10 times or more in the last hour and had a successful login after the failed logons.
EOT
  enabled = False
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = PT1H
    entity_matching_method = Selected
    group_by_entities = ['IP', 'Account']
    group_by_alert_details = ['DisplayName']
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
