resource "my_alert_rule" "rule_323" {
  name = "Explicit MFA Deny"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let aadFunc = (tableName: string) {
    table(tableName)
    | where ResultType == 500121
    | where Status has "MFA Denied; user declined the authentication" or Status has "MFA denied; Phone App Reported Fraud"
    | extend Type = Type
    | extend
        AccountCustomEntity = UserPrincipalName,
        IPCustomEntity = IPAddress,
        URLCustomEntity = ClientAppUsed,
        Time = bin(TimeGenerated, 30m)
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
| extend TimeGeneratedReal = TimeGenerated
| join kind=leftanti (union (SigninLogs
| where AuthenticationRequirement has "multiFactorAuthentication"
| extend AuthenticationStepDetail = tostring(parse_json(parse_json(parse_json(AuthenticationDetails)[1]).authenticationStepResultDetail)), Success = tostring(parse_json(parse_json(parse_json(AuthenticationDetails)[1]).succeeded)), Time = bin(TimeGenerated, 10m)
| where not (AuthenticationStepDetail has ("MFA requirement satisfied by claim in the token"))
| where isnotempty(AuthenticationStepDetail)
| where isnotempty(Success)
| where Success has "true"
| project IPAddress, MfaDetail, AuthenticationStepDetail, Success, UserPrincipalName, Time),(
AADNonInteractiveUserSignInLogs
    | where AuthenticationRequirement has "multiFactorAuthentication"
    | extend Time = bin(TimeGenerated, 30m)
    | project IPAddress, UserPrincipalName, Time)
    | distinct UserPrincipalName, IPAddress, Time)
 on $left.IPAddress == $right.IPAddress and $left.UserPrincipalName == $right.UserPrincipalName and $left.Time == $right.Time
| distinct IPAddress, UserPrincipalName, AppDisplayName, TimeGeneratedReal, ClientAppUsed
| extend AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress, URLCustomEntity = ClientAppUsed
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
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = Explicit MFA Deny
  description = <<EOT
User explicitly denies MFA push, indicating that login was not expected and the account's password may be compromised.
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
