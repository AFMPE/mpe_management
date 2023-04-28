resource "my_alert_rule" "rule_139" {
  name = "Successful Signin from Impossible Travel Activity"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT15M
  query_period = PT15M
  severity = Medium
  query = <<EOF
let CommonUsers = 5;
let Roles = "";
let Address = "";
SecurityAlert
// Get a list of source IP's for the logins
| where TimeGenerated >= ago(15m)
| where DisplayName has "Impossible travel activity"
| where Status != "Dismissed"
| extend Entities = iff(isempty(Entities), todynamic('[{"dummy" : ""}]'), todynamic(Entities))
| mvexpand Entities
| evaluate bag_unpack(Entities, columnsConflict='replace_source')
| extend Type = columnifexists("Type","")
| where Type == "ip"
| extend roles = parse_json(Roles)[0]
| where roles !has "Contextual"
| summarize IP=make_set(Address) by CompromisedEntity
| mv-expand IP
| where IP <> ""
| extend IPAddress = tostring(IP)
// confirm that logins were sucessful by IP
| join kind=inner (union (SigninLogs | where Status has "0" | project IPAddress, AuthenticationRequirement, UserPrincipalName, UserDisplayName),(AADNonInteractiveUserSignInLogs |where Status has "0" | project IPAddress, AuthenticationRequirement, UserPrincipalName, UserDisplayName)) on $left.IPAddress == $right.IPAddress and $left.CompromisedEntity == $right.UserPrincipalName
| distinct CompromisedEntity, IPAddress
// confirm if this is a commonly used IP for logins
| join kind = inner (union (SigninLogs | where TimeGenerated >= ago(30d) | where Status has "0" | project UserPrincipalName, IPAddress),(AADNonInteractiveUserSignInLogs | where TimeGenerated >= ago(30d)|  where Status has "0" | project UserPrincipalName, IPAddress)) on $left.IPAddress == $right.IPAddress
| distinct CompromisedEntity, IPAddress, UserPrincipalName, IPAddress1
// determine if these logins are from the same user or a different user
| extend DifferentUser = iif(CompromisedEntity == UserPrincipalName,true,false)
| summarize count() by DifferentUser, IPAddress, CompromisedEntity
// filter out results if the address is common for other users to authenticate from (attempt to detect VPN)
| extend CommonLogin = iif(DifferentUser == false and count_ >= CommonUsers , true, false)
| where CommonLogin == false
| extend Time = bin(TimeGenerated, 1s)
| distinct Time, CompromisedEntity, IPAddress
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = CompromisedEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPAddress
    }
  }
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = Successful Signin from Impossible Travel Activity
  description = <<EOT
Corralates Successful signins from IP's that are uncommon for other users in the last 30 days. If there are more then 4 successful signins from other users on this IP then this will not alert.
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
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
