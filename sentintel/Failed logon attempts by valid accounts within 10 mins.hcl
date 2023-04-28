resource "my_alert_rule" "rule_114" {
  name = "Failed logon attempts by valid accounts within 10 mins"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT10M
  query_period = PT10M
  severity = Low
  query = <<EOF
let threshold = 20;
let ReasontoSubStatus = datatable(SubStatus:string,Reason:string) [
"0xC000005E", "There are currently no logon servers available to service the logon request.",
"0xC0000064", "User logon with misspelled or bad user account", 
"0xC000006A", "User logon with misspelled or bad password",
"0xC000006D", "Bad user name or password",
"0xC000006E", "Unknown user name or bad password",
"0xC000006F", "User logon outside authorized hours",
"0xC0000070", "User logon from unauthorized workstation",
"0xC0000071", "User logon with expired password",
"0xC0000072", "User logon to account disabled by administrator",
"0xC00000DC", "Indicates the Sam Server was in the wrong state to perform the desired operation",
"0xC0000133", "Clocks between DC and other computer too far out of sync",
"0xC000015B", "The user has not been granted the requested logon type (aka logon right) at this machine",
"0xC000018C", "The logon request failed because the trust relationship between the primary domain and the trusted domain failed",
"0xC0000192", "An attempt was made to logon, but the Netlogon service was not started",
"0xC0000193", "User logon with expired account",
"0xC0000224", "User is required to change password at next logon",
"0xC0000225", "Evidently a bug in Windows and not a risk",
"0xC0000234", "User logon with account locked",
"0xC00002EE", "Failure Reason: An Error occurred during Logon",
"0xC0000413", "Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine"
];
(union isfuzzy=true
(SecurityEvent 
| where EventID == 4625
| where AccountType =~ "User"
| where SubStatus !='0xc0000064' and Account !in ('\\', '-\\-')
// SubStatus '0xc0000064' signifies 'Account name does not exist'
| extend ResourceId = column_ifexists("_ResourceId", _ResourceId), SourceComputerId = column_ifexists("SourceComputerId", SourceComputerId)
| lookup ReasontoSubStatus on SubStatus
| extend coalesce(Reason, strcat('Unknown reason substatus: ', SubStatus))
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), FailedLogonCount = count() by EventID, 
Activity, Computer, Account, TargetAccount, TargetUserName, TargetDomainName, 
LogonType, LogonTypeName, LogonProcessName, Status, SubStatus, Reason, ResourceId, SourceComputerId, WorkstationName, IpAddress
| where FailedLogonCount >= threshold
| extend timestamp = StartTime, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress
),
(
(WindowsEvent 
| where EventID == 4625 and not(EventData has '0xc0000064')
| extend TargetAccount = strcat(tostring(EventData.TargetDomainName),"\\", tostring(EventData.TargetUserName))
| extend TargetUserSid = tostring(EventData.TargetUserSid)
| extend AccountType=case(EventData.TargetUserName endswith "$" or TargetUserSid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"), "Machine", isempty(TargetUserSid), "", "User")
| where AccountType =~ "User"
| extend SubStatus = tostring(EventData.SubStatus)
| where SubStatus !='0xc0000064' and TargetAccount !in ('\\', '-\\-')
// SubStatus '0xc0000064' signifies 'Account name does not exist'
| extend ResourceId = column_ifexists("_ResourceId", _ResourceId), SourceComputerId = column_ifexists("SourceComputerId", "")
| lookup ReasontoSubStatus on SubStatus
| extend coalesce(Reason, strcat('Unknown reason substatus: ', SubStatus))
| extend Activity="4625 - An account failed to log on."
| extend TargetUserName = tostring(EventData.TargetUserName)
| extend TargetDomainName = tostring(EventData.TargetDomainName)
| extend LogonType = tostring(EventData.LogonType)
| extend Status= tostring(EventData.Status)
| extend LogonProcessName = tostring(EventData.LogonProcessName)
| extend WorkstationName = tostring(EventData.WorkstationName)
| extend IpAddress = tostring(EventData.IpAddress)
| extend LogonTypeName=case(LogonType==2,"2 - Interactive", LogonType==3,"3 - Network", LogonType==4, "4 - Batch",LogonType==5, "5 - Service", LogonType==7, "7 - Unlock", LogonType==8, "8 - NetworkCleartext", LogonType==9, "9 - NewCredentials", LogonType==10, "10 - RemoteInteractive", LogonType==11, "11 - CachedInteractive",tostring(LogonType))
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), FailedLogonCount = count() by EventID, 
Activity, Computer,  TargetAccount, TargetUserName, TargetDomainName, 
LogonType, LogonTypeName, LogonProcessName, Status, SubStatus, Reason, ResourceId, SourceComputerId, WorkstationName, IpAddress
| where FailedLogonCount >= threshold
| extend timestamp = StartTime, AccountCustomEntity = TargetAccount, HostCustomEntity = Computer, IPCustomEntity = IpAddress
)))
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
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = Failed logon attempts by valid accounts within 10 mins
  description = <<EOT
Identifies when failed logon attempts are 20 or higher during a 10 minute period (2 failed logons per minute minimum) from valid account.
EOT
  enabled = False
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
