resource "my_alert_rule" "rule_220" {
  name = "Identify SysAid Server web shell creation"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
let timeframe = 1d;
let time_window = 5m;
(union isfuzzy=true
(SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4688
| where Process has_any ("java.exe", "javaw.exe") and CommandLine has "SysAidServer" 
| summarize by ParentProcessName,Process, Account, Computer, CommandLine, timekey= bin(TimeGenerated, time_window), TimeGenerated, SubjectLogonId
| join kind=inner(
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4663
| where Process has_any ("java.exe", "javaw.exe")
| where AccessMask in ('0x2','0x100', '0x10', '0x4')
| where ObjectName endswith ".jsp" 
| summarize by ParentProcessName, Account, Computer, ObjectName, ProcessName, timekey= bin(TimeGenerated, time_window), TimeGenerated, SubjectLogonId)
 on timekey, Computer, SubjectLogonId
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer
),
(DeviceFileEvents 
| where InitiatingProcessFileName has_any ("java.exe", "javaw.exe")  
| where InitiatingProcessCommandLine has "SysAidServer"  
| where FileName endswith ".jsp" 
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingProcessAccountName, HostCustomEntity = DeviceName
)
)
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
  tactics = ['InitialAccess']
  techniques = ['T1190']
  display_name = Identify SysAid Server web shell creation
  description = <<EOT
This query looks for potential webshell creation by the threat actor Mercury after the sucessful exploitation of SysAid server. 
Reference:  https://www.microsoft.com/security/blog/2022/08/25/mercury-leveraging-log4j-2-vulnerabilities-in-unpatched-systems-to-target-israeli-organizations/
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
