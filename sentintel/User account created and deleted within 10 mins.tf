resource "my_alert_rule" "rule_66" {
  name = "User account created and deleted within 10 mins"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let timeframe = 1d;
let spanoftime = 10m;
let threshold = 0;
 (union isfuzzy=true
 (SecurityEvent
| where TimeGenerated > ago(timeframe+spanoftime)
// A user account was created
| where EventID == 4720
| where AccountType =~ "User"
| project creationTime = TimeGenerated, CreateEventID = EventID, CreateActivity = Activity, Computer, TargetUserName, UserPrincipalName, 
AccountUsedToCreate = SubjectAccount, SIDofAccountUsedToCreate = SubjectUserSid, TargetAccount = tolower(TargetAccount), TargetSid
),
(
WindowsEvent
| where TimeGenerated > ago(timeframe+spanoftime)
// A user account was created
| where EventID == 4720
| extend SubjectUserSid = tostring(EventData.SubjectUserSid)
| extend AccountType=case(EventData.SubjectUserName endswith "$" or SubjectUserSid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"), "Machine", isempty(SubjectUserSid), "", "User")
| where AccountType =~ "User"
| extend SubjectAccount = strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend TargetAccount = strcat(EventData.TargetDomainName,"\\", EventData.TargetUserName)
| extend TargetSid = tostring(EventData.TargetSid)
| extend UserPrincipalName = tostring(EventData.UserPrincipalName)
| extend Activity = "4720 - A user account was created."
| extend TargetUserName = tostring(EventData.TargetUserName) 
| project creationTime = TimeGenerated, CreateEventID = EventID, CreateActivity = Activity, Computer, TargetUserName, UserPrincipalName, 
AccountUsedToCreate = SubjectAccount, SIDofAccountUsedToCreate = SubjectUserSid, TargetAccount = tolower(TargetAccount), TargetSid  
))
| join kind= inner (
  (union isfuzzy=true
  (SecurityEvent
  | where TimeGenerated > ago(timeframe)
  // A user account was deleted
  | where EventID == 4726
| where AccountType == "User"
| project deletionTime = TimeGenerated, DeleteEventID = EventID, DeleteActivity = Activity, Computer, TargetUserName, UserPrincipalName, 
AccountUsedToDelete = SubjectAccount, SIDofAccountUsedToDelete = SubjectUserSid, TargetAccount = tolower(TargetAccount), TargetSid
),
(WindowsEvent
| where TimeGenerated > ago(timeframe)
  // A user account was deleted
| where EventID == 4726
| extend SubjectUserSid = tostring(EventData.SubjectUserSid)
| extend SubjectAccount = strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend AccountType=case(SubjectAccount endswith "$" or SubjectUserSid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"), "Machine", isempty(SubjectUserSid), "", "User")
| where AccountType == "User"
| extend TargetSid = tostring(EventData.TargetSid)
| extend UserPrincipalName = tostring(EventData.UserPrincipalName)
| extend Activity = "4726 - A user account was deleted."
| extend TargetUserName = tostring(EventData.TargetUserName) 
| extend TargetAccount = strcat(EventData.TargetDomainName,"\\", EventData.TargetUserName)
| project deletionTime = TimeGenerated, DeleteEventID = EventID, DeleteActivity = Activity, Computer, TargetUserName, UserPrincipalName, AccountUsedToDelete = SubjectAccount, SIDofAccountUsedToDelete = SubjectUserSid, TargetAccount = tolower(TargetAccount), TargetSid))
) on Computer, TargetAccount
| where deletionTime - creationTime < spanoftime
| extend TimeDelta = deletionTime - creationTime
| where tolong(TimeDelta) >= threshold
| project TimeDelta, creationTime, CreateEventID, CreateActivity, Computer, TargetAccount, TargetSid, UserPrincipalName, AccountUsedToCreate, SIDofAccountUsedToCreate,
deletionTime, DeleteEventID, DeleteActivity, AccountUsedToDelete, SIDofAccountUsedToDelete
| extend timestamp = creationTime, AccountCustomEntity = AccountUsedToCreate, HostCustomEntity = Computer
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
      identifier = Sid
      column_name = SIDofAccountUsedToCreate
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
  }
  tactics = ['Persistence', 'PrivilegeEscalation']
  techniques = ['T1078', 'T1098']
  display_name = User account created and deleted within 10 mins
  description = <<EOT
Identifies when a user account is created and then deleted within 10 minutes. This can be an indication of compromise and
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
