resource "my_alert_rule" "rule_109" {
  name = "User account enabled and disabled within 10 mins"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let timeframe = 1d;
let spanoftime = 10m;
let threshold = 0;
SecurityEvent
| where TimeGenerated > ago(timeframe+spanoftime)
// A user account was enabled
| where EventID == 4722
| where AccountType =~ "User"
| where TargetAccount !hassuffix "$"
| project EnableTime = TimeGenerated, EnableEventID = EventID, EnableActivity = Activity, Computer, UserPrincipalName, 
AccountUsedToEnable = SubjectAccount, SIDofAccountUsedToEnable = SubjectUserSid, TargetAccount = tolower(TargetAccount), TargetSid
| join kind= inner (
  SecurityEvent
  | where TimeGenerated > ago(timeframe)
  // A user account was disabled
  | where EventID == 4725
| where AccountType =~ "User"
| project DisableTime = TimeGenerated, DisableEventID = EventID, DisableActivity = Activity, Computer, UserPrincipalName, 
AccountUsedToDisable = SubjectAccount, SIDofAccountUsedToDisable = SubjectUserSid, TargetAccount = tolower(TargetAccount), TargetSid
) on Computer, TargetAccount
| where DisableTime - EnableTime < spanoftime
| extend TimeDelta = DisableTime - EnableTime
| where tolong(TimeDelta) >= threshold
| project TimeDelta, EnableTime, EnableEventID, EnableActivity, Computer, TargetAccount, TargetSid, UserPrincipalName, AccountUsedToEnable, SIDofAccountUsedToEnable, 
DisableTime, DisableEventID, DisableActivity, AccountUsedToDisable, SIDofAccountUsedToDisable
| extend timestamp = EnableTime, AccountCustomEntity = AccountUsedToEnable, HostCustomEntity = Computer
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
      identifier = Sid
      column_name = SIDofAccountUsedToEnable
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
  }
  tactics = ['Persistence', 'PrivilegeEscalation']
  techniques = ['T1078', 'T1098']
  display_name = User account enabled and disabled within 10 mins
  description = <<EOT
Identifies when a user account is enabled and then disabled within 10 minutes. This can be an indication of compromise and
an adversary attempting to hide in the noise.
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
