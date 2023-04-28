resource "my_alert_rule" "rule_330" {
  name = "Successful Signin from Unfamiliar signin properties"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT15M
  query_period = PT15M
  severity = Medium
  query = <<EOF
SecurityAlert
| where DisplayName == "Unfamiliar sign-in properties"
| extend
    IPAddress = tostring(parse_json(ExtendedProperties)["Client IP Address"]),
    Location = tostring(parse_json(ExtendedProperties)["Client Location"]),
    Id = tostring(parse_json(ExtendedProperties)["Request Id"])
| join kind=leftouter (union
        (SigninLogs
        | project Id, UserPrincipalName),
        (AADNonInteractiveUserSignInLogs
        | project Id, UserPrincipalName))
    on $left.Id == $right.Id
| join kind=inner (union
        (SigninLogs
        | where Status has "0"
        | project IPAddress, AuthenticationRequirement, UserPrincipalName, UserDisplayName, Status, AppDisplayName, ClientAppUsed),
        (AADNonInteractiveUserSignInLogs
        | where Status has "0"
        | project IPAddress, AuthenticationRequirement, UserPrincipalName, UserDisplayName))
    on $left.IPAddress == $right.IPAddress and $left.UserPrincipalName == $right.UserPrincipalName 
| extend Time = bin(TimeGenerated, 1s)
| distinct Time, IPAddress, Location, UserPrincipalName, UserDisplayName, AuthenticationRequirement, AppDisplayName, ClientAppUsed

EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = UserDisplayName
      identifier = DisplayName
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
  display_name = Successful Signin from Unfamiliar sign-in properties
  description = <<EOT
This rule parses Unfamiliar sign-in properties alerts and correlates successful logins.
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
