resource "my_alert_rule" "rule_69" {
  name = "Dormant User Update MFA and Logs In"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
let starttime = todatetime('{{StartTimeISO}}');
let endtime = todatetime('{{EndTimeISO}}');
let lookback = endtime - 14d;
let active_users = (
    SigninLogs
    | where TimeGenerated between(lookback..starttime)
    | where ResultType == 0
    | extend UserPrincipalName == tolower(UserPrincipalName)
    | summarize by UserId);
AuditLogs
| where TimeGenerated between(starttime..endtime)
// Get users where they added MFA
| where OperationName =~ "User registered security info"
| extend TargetUser = tolower(tostring(TargetResources[0].userPrincipalName))
| extend UserId = tostring(TargetResources[0].id)
// Check and see if this activity was from a user who is considered not active
| where UserId !in (active_users)
// Further reduce FP by just looking at users who have successfully logged in recently as well (avoiding hits for users adding MFA but not actually logging in)
| join kind=inner (SigninLogs | where TimeGenerated  between(starttime..endtime) | where ResultType == 0 | summarize max(TimeGenerated), make_set(IPAddress), make_set(UserAgent), make_set(LocationDetails) by UserPrincipalName, UserId
) on UserId
| extend LogonLocation = set_LocationDetails[0], LogonUserAgent = set_UserAgent[0], LogonIP = set_IPAddress[0]
| project-rename MostRecentLogon = max_TimeGenerated
| project-reorder TimeGenerated, TargetUser, OperationName, ResultDescription, MostRecentLogon, LogonUserAgent, LogonLocation, LogonIP
| extend AccountCustomEntity = TargetUser, IPCustomEntity = LogonIP

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
  tactics = ['Persistence']
  techniques = ['T1556']
  display_name = Dormant User Update MFA and Logs In
  description = <<EOT
'This querys look for users accounts that have not been successfully logged into recently, who then have a MFA method added or updated before logging in.
Threat actors may look to re-activate dormant accounts and use them for access by adding MFA methods in the hope that changes to such dormant accounts may go un-noticed.'

EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = None
}
