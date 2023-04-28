resource "my_alert_rule" "rule_94" {
  name = "Successful Signin from Atypical Travel"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT15M
  query_period = PT15M
  severity = Medium
  query = <<EOF
SecurityAlert
| where DisplayName == "Atypical travel"
| extend IPAddress = tostring(parse_json(parse_json(Entities)[3]).Address), Country = tostring(parse_json(parse_json(parse_json(Entities)[3]).Location).CountryCode), State = tostring(parse_json(parse_json(parse_json(Entities)[3]).Location).State), City = tostring(parse_json(parse_json(parse_json(Entities)[3]).Location).City), Id = tostring(parse_json(ExtendedProperties)["Request Id"]), PreviousIP = tostring(parse_json(ExtendedProperties)["Previous IP Address"])
| join kind=leftouter (union(SigninLogs 
| project Id, UserPrincipalName),(AADNonInteractiveUserSignInLogs 
| project Id, UserPrincipalName)) on $left.Id == $right.Id
| join kind=inner (union(SigninLogs | where Status has "0" 
| project IPAddress, AuthenticationRequirement, UserPrincipalName, UserDisplayName, Status, AppDisplayName, ClientAppUsed),(AADNonInteractiveUserSignInLogs 
|where Status has "0" 
| project IPAddress, AuthenticationRequirement, UserPrincipalName, UserDisplayName)) on $left.IPAddress == $right.IPAddress and $left.UserPrincipalName == $right.UserPrincipalName
| project-rename CurrentCountry=Country, CurrentCity=City, CurrentState=State, UserPrincipalName
| extend Time = bin(TimeGenerated, 1s)
| distinct Time, CurrentState, CurrentCity, CurrentCountry, IPAddress, PreviousIP, UserPrincipalName, UserDisplayName


EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = UserDisplayName
      identifier = AadUserId
      column_name = UserPrincipalName
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPAddress
    }
  }
  tactics = ['CredentialAccess', 'InitialAccess']
  techniques = ['T1133']
  display_name = Successful Signin from Atypical Travel
  description = <<EOT
This rule looks at atypical travel alerts and correlates them with successful logins. 
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = PT15M
    entity_matching_method = Selected
    group_by_entities = ['Account', 'IP']
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
