resource "my_alert_rule" "rule_111" {
  name = "Microsoft Build Engine Started by a Script Process"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
union
(SecurityEvent
| where Channel == "Security"
| where AccountType == "User"
| where EventID == "4688"
| where ParentProcessName contains "cmd" or ParentProcessName contains "powershell"
| where Process == "MSBuild.exe"
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
),
(DeviceProcessEvents
| where InitiatingProcessFileName has_any ("cmd", "powershell")
| where FileName has "MSBuild.exe"
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName)
| where not(ProcessCommandLine has_any ("C:\\Program Files (x86)\\Motorola\\PremierOne"))
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
  tactics = ['DefenseEvasion', 'Execution']
  techniques = ['T1036']
  display_name = Microsoft Build Engine Started by a Script Process
  description = <<EOT
'An instance of MSBuild, the Microsoft Build Engine, was started by a script or the Windows command interpreter. This behavior is unusual and is sometimes used by malicious payloads.'

EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
