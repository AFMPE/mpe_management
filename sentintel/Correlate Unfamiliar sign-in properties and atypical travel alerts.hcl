resource "my_alert_rule" "rule_266" {
  name = "Correlate Unfamiliar sign-in properties and atypical travel alerts"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = High
  query = <<EOF
let Alert1 = 
SecurityAlert
| where TimeGenerated > ago(1d)
| where ProductName == "Azure Active Directory Identity Protection"
| where AlertName == "Unfamiliar sign-in properties"
| mv-expand Entity = todynamic(Entities)
| where Entity.Type == "account"
| extend AadTenantId = tostring(Entity.AadTenantId)
| extend AadUserId = tostring(Entity.AadUserId)
| join kind=inner (
IdentityInfo
| distinct AccountTenantId, AccountObjectId, AccountUPN, AccountDisplayName
| extend UserName = AccountDisplayName
| extend UserAccount = AccountUPN
| where isnotempty(AccountDisplayName) and isnotempty(UserAccount)
| project AccountTenantId, AccountObjectId, UserAccount, UserName
)
on
$left.AadTenantId == $right.AccountTenantId,
$left.AadUserId == $right.AccountObjectId
| extend CompromisedEntity = iff(CompromisedEntity == "N/A" or isempty(CompromisedEntity), UserAccount, CompromisedEntity)
| extend Alert1Time = TimeGenerated
| extend Alert1 = AlertName
| extend Alert1Severity = AlertSeverity
| project AadTenantId, AadUserId, AccountTenantId, AccountObjectId, Alert1, Alert1Severity, Alert1Time, UserAccount, UserName
;
let Alert2 = 
SecurityAlert
| where TimeGenerated > ago(1d)
| where ProductName == "Azure Active Directory Identity Protection"
| where AlertName == "Atypical travel"
| mv-expand Entity = todynamic(Entities)
| where Entity.Type == "account"
| extend AadTenantId = tostring(Entity.AadTenantId)
| extend AadUserId = tostring(Entity.AadUserId)
| join kind=inner (
IdentityInfo
| distinct AccountTenantId, AccountObjectId, AccountUPN, AccountDisplayName
| extend UserName = AccountDisplayName
| extend UserAccount = AccountUPN
| where isnotempty(AccountDisplayName) and isnotempty(UserAccount)
| project AccountTenantId, AccountObjectId, UserAccount, UserName
)
on
$left.AadTenantId == $right.AccountTenantId,
$left.AadUserId == $right.AccountObjectId
| extend CompromisedEntity = iff(CompromisedEntity == "N/A" or isempty(CompromisedEntity), UserAccount, CompromisedEntity)
| extend Alert2Time = TimeGenerated
| extend Alert2 = AlertName
| extend Alert2Severity = AlertSeverity
| extend CurrentLocation = strcat(tostring(parse_json(tostring(parse_json(Entities)[2].Location)).CountryCode), "|", tostring(parse_json(tostring(parse_json(Entities)[2].Location)).State), "|", tostring(parse_json(tostring(parse_json(Entities)[2].Location)).City))
| extend PreviousLocation = strcat(tostring(parse_json(tostring(parse_json(Entities)[3].Location)).CountryCode), "|", tostring(parse_json(tostring(parse_json(Entities)[3].Location)).State), "|", tostring(parse_json(tostring(parse_json(Entities)[3].Location)).City))
| extend CurrentIPAddress = tostring(parse_json(Entities)[2].Address)
| extend PreviousIPAddress = tostring(parse_json(Entities)[3].Address)
| project AadTenantId, AadUserId, AccountTenantId, AccountObjectId, Alert2, Alert2Severity, Alert2Time, CurrentIPAddress, PreviousIPAddress, CurrentLocation, PreviousLocation, UserAccount, UserName
;
Alert1
| join kind=inner Alert2 on UserAccount
| where abs(datetime_diff('minute', Alert1Time, Alert2Time)) <=10
| extend TimeDelta = Alert1Time - Alert2Time
| project UserAccount, Alert1, Alert1Time, Alert1Severity, Alert2, Alert2Time, Alert2Severity, TimeDelta, CurrentLocation, PreviousLocation, CurrentIPAddress, PreviousIPAddress, UserName
| extend AccountCustomEntity = UserAccount
| extend IPCustomEntity = CurrentIPAddress
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
  tactics = ['InitialAccess']
  techniques = ['T1078']
  display_name = Correlate Unfamiliar sign-in properties and atypical travel alerts
  description = <<EOT
The combination of an Unfamiliar sign-in properties alert and an Atypical travel alert about the same user within a +10m or -10m window is considered a high severity incident.
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
