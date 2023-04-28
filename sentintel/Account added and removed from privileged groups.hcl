resource "my_alert_rule" "rule_108" {
  name = "Account added and removed from privileged groups"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let WellKnownLocalSID = "S-1-5-32-5[0-9][0-9]$";
let WellKnownGroupSID = "S-1-5-21-[0-9]*-[0-9]*-[0-9]*-5[0-9][0-9]$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1102$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1103$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-498$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1000$";
let AC_Add = 
(union isfuzzy=true 
(SecurityEvent
// Event ID related to member addition.
| where EventID in (4728, 4732,4756) 
| where TargetSid matches regex WellKnownLocalSID or TargetSid matches regex WellKnownGroupSID  
| parse EventData with * '"MemberName">' * '=' AccountAdded ",OU" *
| where isnotempty(AccountAdded)
| extend GroupAddedTo = TargetUserName, AddingAccount = Account 
| extend  AccountAdded_GroupAddedTo_AddingAccount = strcat(AccountAdded, "||", GroupAddedTo, "||", AddingAccount )
| project AccountAdded_GroupAddedTo_AddingAccount, AccountAddedTime = TimeGenerated
),
(WindowsEvent
// Event ID related to member addition.
| where EventID in (4728, 4732,4756) 
| extend TargetSid = tostring(EventData.TargetSid)
| where TargetSid matches regex WellKnownLocalSID or TargetSid matches regex WellKnownGroupSID  
| parse EventData.MemberName with * '"MemberName">' * '=' AccountAdded ",OU" *
| where isnotempty(AccountAdded)
| extend TargetUserName = tostring(EventData.TargetUserName)
| extend AddingAccount =  strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend GroupAddedTo = TargetUserName
| extend  AccountAdded_GroupAddedTo_AddingAccount = strcat(AccountAdded, "||", GroupAddedTo, "||", AddingAccount )
| project AccountAdded_GroupAddedTo_AddingAccount, AccountAddedTime = TimeGenerated
)
);
let AC_Remove = 
( union isfuzzy=true 
(SecurityEvent
// Event IDs related to member removal.
| where EventID in (4729,4733,4757)
| where TargetSid matches regex WellKnownLocalSID or TargetSid matches regex WellKnownGroupSID 
| parse EventData with * '"MemberName">' * '=' AccountRemoved ",OU" * 
| where isnotempty(AccountRemoved)
| extend GroupRemovedFrom = TargetUserName, RemovingAccount = Account
| extend AccountRemoved_GroupRemovedFrom_RemovingAccount = strcat(AccountRemoved, "||", GroupRemovedFrom, "||", RemovingAccount)
| project AccountRemoved_GroupRemovedFrom_RemovingAccount, AccountRemovedTime = TimeGenerated, Computer, RemovedAccountId = tolower(AccountRemoved), 
RemovedByUser = SubjectUserName, RemovedByUserLogonId = SubjectLogonId,  GroupRemovedFrom = TargetUserName, TargetDomainName
),
(WindowsEvent
// Event IDs related to member removal.
| where EventID in (4729,4733,4757)
| extend TargetSid = tostring(EventData.TargetSid)
| where TargetSid matches regex WellKnownLocalSID or TargetSid matches regex WellKnownGroupSID 
| parse EventData.MemberName with * '"MemberName">' * '=' AccountRemoved ",OU" * 
| where isnotempty(AccountRemoved)
| extend TargetUserName = tostring(EventData.TargetUserName)
| extend RemovingAccount =  strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend GroupRemovedFrom = TargetUserName
| extend AccountRemoved_GroupRemovedFrom_RemovingAccount = strcat(AccountRemoved, "||", GroupRemovedFrom, "||", RemovingAccount)
| extend SubjectUserName = tostring(EventData.SubjectUserName)
| extend SubjectLogonId = tostring(EventData.SubjectLogonId)
| extend TargetDomainName = tostring(EventData.TargetDomainName)
| project AccountRemoved_GroupRemovedFrom_RemovingAccount, AccountRemovedTime = TimeGenerated, Computer, RemovedAccountId = tolower(AccountRemoved), 
RemovedByUser = SubjectUserName, RemovedByUserLogonId = SubjectLogonId,  GroupRemovedFrom = TargetUserName, TargetDomainName
)); 
AC_Add 
| join kind= inner AC_Remove on $left.AccountAdded_GroupAddedTo_AddingAccount == $right.AccountRemoved_GroupRemovedFrom_RemovingAccount 
| extend DurationinSecondAfter_Removed = datetime_diff ('second', AccountRemovedTime, AccountAddedTime)
| where DurationinSecondAfter_Removed > 0
| project-away AccountRemoved_GroupRemovedFrom_RemovingAccount
| extend timestamp = AccountAddedTime, AccountCustomEntity = RemovedAccountId, HostCustomEntity = Computer
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
  }
  tactics = ['Persistence', 'PrivilegeEscalation']
  techniques = ['T1098', 'T1078']
  display_name = Account added and removed from privileged groups
  description = <<EOT
Identifies accounts that are added to privileged group and then quickly removed, which could be a sign of compromise.' 
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
