resource "my_alert_rule" "rule_122" {
  name = "Sign-ins from IPs that attempt sign-ins to disabled accounts"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let aadFunc = (tableName:string){
  table(tableName)
  | where ResultType == "50057" 
  | where ResultDescription == "User account is disabled. The account has been disabled by an administrator." 
  | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), disabledAccountLoginAttempts = count(), 
  disabledAccountsTargeted = dcount(UserPrincipalName), applicationsTargeted = dcount(AppDisplayName), disabledAccountSet = make_set(UserPrincipalName), 
  applicationSet = make_set(AppDisplayName) by IPAddress, Type
  | order by disabledAccountLoginAttempts desc
  | join kind= leftouter (
      // Consider these IPs suspicious - and alert any related  successful sign-ins
      table(tableName)
      | where ResultType == 0
      | summarize successfulAccountSigninCount = dcount(UserPrincipalName), successfulAccountSigninSet = make_set(UserPrincipalName, 15) by IPAddress, Type
      // Assume IPs associated with sign-ins from 100+ distinct user accounts are safe
      | where successfulAccountSigninCount < 100
  ) on IPAddress  
  // IPs from which attempts to authenticate as disabled user accounts originated, and had a non-zero success rate for some other account
  | where isnotempty(successfulAccountSigninCount)
  | project StartTime, EndTime, IPAddress, disabledAccountLoginAttempts, disabledAccountsTargeted, disabledAccountSet, applicationSet, 
  successfulAccountSigninCount, successfulAccountSigninSet, Type
  | order by disabledAccountLoginAttempts
  | extend timestamp = StartTime, IPCustomEntity = IPAddress
  };
  let aadSignin = aadFunc("SigninLogs");
  let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
  union isfuzzy=true aadSignin, aadNonInt
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = successfulAccountSigninSet
    }
  }
  tactics = ['InitialAccess', 'Persistence']
  techniques = ['T1078', 'T1098']
  display_name = Sign-ins from IPs that attempt sign-ins to disabled accounts
  description = <<EOT
Identifies IPs with failed attempts to sign in to one or more disabled accounts signed in successfully to another account.
References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes
50057 - User account is disabled. The account has been disabled by an administrator.
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
