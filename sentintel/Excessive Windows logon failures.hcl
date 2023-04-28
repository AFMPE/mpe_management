resource "my_alert_rule" "rule_37" {
  name = "Excessive Windows logon failures"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P8D
  severity = Low
  query = <<EOF
let starttime = 8d;
let endtime = 1d;
let threshold = 0.333;
let countlimit = 50;
SecurityEvent
| where TimeGenerated >= ago(endtime)
| where EventID == 4625 and AccountType =~ "User"
| where IpAddress !in ("127.0.0.1", "::1")
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), CountToday = count() by EventID, Account, LogonTypeName, SubStatus, AccountType, Computer, WorkstationName, IpAddress, Process
| join kind=leftouter (
    SecurityEvent 
    | where TimeGenerated between (ago(starttime) .. ago(endtime))
    | where EventID == 4625 and AccountType =~ "User"
    | where IpAddress !in ("127.0.0.1", "::1")
    | summarize CountPrev7day = count() by EventID, Account, LogonTypeName, SubStatus, AccountType, Computer, WorkstationName, IpAddress
) on EventID, Account, LogonTypeName, SubStatus, AccountType, Computer, WorkstationName, IpAddress
| where CountToday >= coalesce(CountPrev7day,0)*threshold and CountToday >= countlimit
//SubStatus Codes are detailed here - https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4625
| extend Reason = case(
SubStatus =~ '0xC000005E', 'There are currently no logon servers available to service the logon request.',
SubStatus =~ '0xC0000064', 'User logon with misspelled or bad user account',
SubStatus =~ '0xC000006A', 'User logon with misspelled or bad password',    
SubStatus =~ '0xC000006D', 'Bad user name or password',
SubStatus =~ '0xC000006E', 'Unknown user name or bad password',
SubStatus =~ '0xC000006F', 'User logon outside authorized hours',
SubStatus =~ '0xC0000070', 'User logon from unauthorized workstation',
SubStatus =~ '0xC0000071', 'User logon with expired password',
SubStatus =~ '0xC0000072', 'User logon to account disabled by administrator',
SubStatus =~ '0xC00000DC', 'Indicates the Sam Server was in the wrong state to perform the desired operation',  
SubStatus =~ '0xC0000133', 'Clocks between DC and other computer too far out of sync',
SubStatus =~ '0xC000015B', 'The user has not been granted the requested logon type (aka logon right) at this machine',
SubStatus =~ '0xC000018C', 'The logon request failed because the trust relationship between the primary domain and the trusted domain failed',
SubStatus =~ '0xC0000192', 'An attempt was made to logon, but the Netlogon service was not started',
SubStatus =~ '0xC0000193', 'User logon with expired account',
SubStatus =~ '0xC0000224', 'User is required to change password at next logon',
SubStatus =~ '0xC0000225', 'Evidently a bug in Windows and not a risk',
SubStatus =~ '0xC0000234', 'User logon with account locked',
SubStatus =~ '0xC00002EE', 'Failure Reason: An Error occurred during Logon',
SubStatus =~ '0xC0000413', 'Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine',
strcat('Unknown reason substatus: ', SubStatus))
| extend WorkstationName = iff(WorkstationName == "-" or isempty(WorkstationName), Computer , WorkstationName) 
| project StartTime, EndTime, EventID, Account, LogonTypeName, SubStatus, Reason, AccountType, Computer, WorkstationName, IpAddress, CountToday, CountPrev7day, Avg7Day = round(CountPrev7day*1.00/7,2), Process
| summarize StartTime = min(StartTime), EndTime = max(EndTime), Computer = make_set(Computer,128), IpAddressList = make_set(IpAddress,128), sum(CountToday), sum(CountPrev7day), avg(Avg7Day) 
by EventID, Account, LogonTypeName, SubStatus, Reason, AccountType, WorkstationName, Process
| order by sum_CountToday desc nulls last 
| extend timestamp = StartTime, AccountCustomEntity = Account, HostCustomEntity = WorkstationName
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
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = Process
    }
  }
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = Excessive Windows logon failures
  description = <<EOT
User has over 50 Windows logon failures today and at least 33% of the count of logon failures over the previous 7 days.
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