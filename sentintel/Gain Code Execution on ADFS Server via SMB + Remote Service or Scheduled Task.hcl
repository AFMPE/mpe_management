resource "my_alert_rule" "rule_203" {
  name = "Gain Code Execution on ADFS Server via SMB + Remote Service or Scheduled Task"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P7D
  severity = Medium
  query = <<EOF
let timeframe = 1d;
// Adjust for a longer timeframe for identifying ADFS Servers
let lookback = 6d;
// Identify ADFS Servers
let ADFS_Servers = (
SecurityEvent
| where TimeGenerated > ago(timeframe+lookback)
| where EventID == 4688 and SubjectLogonId != "0x3e4"
| where NewProcessName has "Microsoft.IdentityServer.ServiceHost.exe"
| distinct Computer
);
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where Computer in~ (ADFS_Servers)
| where Account !endswith "$"
// Check for scheduled task events
| where EventID in (4697, 4698, 4699, 4700, 4701, 4702)
| extend EventDataParsed = parse_xml(EventData)
| extend SubjectLogonId = tostring(EventDataParsed.EventData.Data[3]["#text"])
// Check specifically for access to IPC$ share and PIPE\svcctl and PIPE\atsvc for Service Control Services and Schedule Control Services
| union (
    SecurityEvent
    | where TimeGenerated > ago(timeframe)
    | where Computer in~ (ADFS_Servers)
    | where Account !endswith "$"
    | where EventID == 5145
    | where RelativeTargetName =~ "svcctl" or RelativeTargetName  =~ "atsvc"
)
// Check for lateral movement
| join kind=inner
(SecurityEvent
| where TimeGenerated > ago(timeframe)
| where Account !endswith "$"
| where EventID == 4624 and LogonType == 3
) on $left.SubjectLogonId == $right.TargetLogonId
| project TimeGenerated, Account, Computer, EventID, RelativeTargetName
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account
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
  tactics = ['LateralMovement']
  techniques = ['T1210']
  display_name = Gain Code Execution on ADFS Server via SMB + Remote Service or Scheduled Task
  description = <<EOT
This query detects instances where an attacker has gained the ability to execute code on an ADFS Server through SMB and Remote Service or Scheduled Task.
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
