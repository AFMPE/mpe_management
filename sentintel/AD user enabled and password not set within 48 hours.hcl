resource "my_alert_rule" "rule_176" {
  name = "AD user enabled and password not set within 48 hours"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P3D
  severity = Low
  query = <<EOF
let starttime = 3d;
let SecEvents = materialize ( SecurityEvent | where TimeGenerated >= ago(starttime)
| where EventID in (4722,4723) | where TargetUserName !endswith "$"
| project TimeGenerated, EventID, Activity, Computer, TargetAccount, TargetSid, SubjectAccount, SubjectUserSid);
let userEnable = SecEvents
| extend EventID4722Time = TimeGenerated
// 4722: User Account Enabled
| where EventID == 4722
| project Time_Event4722 = TimeGenerated, TargetAccount, TargetSid, SubjectAccount_Event4722 = SubjectAccount, SubjectUserSid_Event4722 = SubjectUserSid, Activity_4722 = Activity, Computer_4722 = Computer;
let userPwdSet = SecEvents
// 4723: Attempt made by user to set password
| where EventID == 4723
| project Time_Event4723 = TimeGenerated, TargetAccount, TargetSid, SubjectAccount_Event4723 = SubjectAccount, SubjectUserSid_Event4723 = SubjectUserSid, Activity_4723 = Activity, Computer_4723 = Computer;
userEnable | join kind=leftouter userPwdSet on TargetAccount, TargetSid
| extend PasswordSetAttemptDelta_Min = datetime_diff('minute', Time_Event4723, Time_Event4722)
| where PasswordSetAttemptDelta_Min > 2880 or isempty(PasswordSetAttemptDelta_Min)
| project-away TargetAccount1, TargetSid1
| extend Reason = @"User either has not yet attempted to set the initial password after account was enabled or it occurred after 48 hours"
| order by Time_Event4722 asc 
| extend timestamp = Time_Event4722, AccountCustomEntity = TargetAccount, HostCustomEntity = Computer_4722
| project-reorder Time_Event4722, Time_Event4723, PasswordSetAttemptDelta_Min, TargetAccount, TargetSid
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
      identifier = Sid
      column_name = TargetSid
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
  }
  tactics = ['Persistence']
  techniques = ['T1098']
  display_name = AD user enabled and password not set within 48 hours
  description = <<EOT
Identifies when an account is enabled with a default password and the password is not set by the user within 48 hours.
Effectively, there is an event 4722 indicating an account was enabled and within 48 hours, no event 4723 occurs which 
indicates there was no attempt by the user to set the password. This will show any attempts (success or fail) that occur 
after 48 hours, which can indicate too long of a time period in setting the password to something that only the user knows.
It is recommended that this time period is adjusted per your internal company policy.
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
