resource "my_alert_rule" "rule_334" {
  name = "Multiple RDP connections from Single System"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P8D
  severity = Low
  query = <<EOF
let endtime = 1d;
let starttime = 8d;
let threshold = 2.0;
(union isfuzzy=true
(SecurityEvent
| where TimeGenerated >= ago(endtime)
| where EventID == 4624 and LogonType == 10
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ComputerCountToday = dcount(Computer), ComputerSet = makeset(Computer), ProcessSet = makeset(ProcessName)
by Account, IpAddress, AccountType, Activity, LogonTypeName),
(WindowsEvent
| where TimeGenerated >= ago(endtime)
| where EventID == 4624 
| extend LogonType = tostring(EventData.LogonType)
| where  LogonType == 10
| extend ProcessName = tostring(EventData.ProcessName)
| extend Account = strcat(tostring(EventData.TargetDomainName),"\\", tostring(EventData.TargetUserName))
| extend IpAddress = tostring(EventData.IpAddress)
| extend TargetUserSid = tostring(EventData.TargetUserSid)
| extend AccountType=case(Account endswith "$" or TargetUserSid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"), "Machine", isempty(TargetUserSid), "", "User")
| extend Activity="4624 - An account was successfully logged on."
| extend LogonTypeName="10 - RemoteInteractive"
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ComputerCountToday = dcount(Computer), ComputerSet = makeset(Computer), ProcessSet = makeset(ProcessName)
by Account, IpAddress, AccountType, Activity, LogonTypeName)
)
| join kind=inner (
(union isfuzzy=true
(SecurityEvent
| where TimeGenerated >= ago(starttime) and TimeGenerated < ago(endtime)
| where EventID == 4624 and LogonType == 10
| summarize ComputerCountPrev7Days = dcount(Computer) by Account = tolower(Account), IpAddress
),
( WindowsEvent
| where TimeGenerated >= ago(starttime) and TimeGenerated < ago(endtime)
| where EventID == 4624  and EventData has ("10")
| extend LogonType = toint(EventData.LogonType)
| where  LogonType == 10
| extend Account = strcat(tostring(EventData.TargetDomainName),"\\", tostring(EventData.TargetUserName))
| extend IpAddress = tostring(EventData.IpAddress)
| summarize ComputerCountPrev7Days = dcount(Computer) by Account = tolower(Account), IpAddress)
)
) on Account, IpAddress
| extend Ratio = iff(isempty(ComputerCountPrev7Days), toreal(ComputerCountToday), ComputerCountToday / (ComputerCountPrev7Days * 1.0))
// Where the ratio of today to previous 7 days is more than double.
| where Ratio > threshold
| project StartTimeUtc, EndTimeUtc, Account, IpAddress, ComputerSet, ComputerCountToday, ComputerCountPrev7Days, Ratio, AccountType, Activity, LogonTypeName, ProcessSet
| extend timestamp = StartTimeUtc, AccountCustomEntity = Account, IPCustomEntity = IpAddress
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
  tactics = ['LateralMovement']
  techniques = ['T1021']
  display_name = Multiple RDP connections from Single System
  description = <<EOT
Identifies when an RDP connection is made to multiple systems and above the normal for the previous 7 days.
Connections from the same system with the same account within the same day.
RDP connections are indicated by the EventID 4624 with LogonType = 10
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
