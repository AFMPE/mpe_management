resource "my_alert_rule" "rule_360" {
  name = "Microsoft Build Engine Started an Unusual Process"
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
| where ParentProcessName has "msbuild.exe"
| where Process has_any("powershell", "iexplore", "csc")
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
),
(DeviceProcessEvents
| where InitiatingProcessFileName has "msbuild.exe"
| where ProcessCommandLine has_any("powershell", "iexplore", "csc")
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
)
| where not(InitiatingProcessCommandLine has_any ("C:\\Program Files (x86)\\Motorola\\PremierOne", "MSBuild.exe"))
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
  tactics = ['DefenseEvasion']
  techniques = ['T1036']
  display_name = Microsoft Build Engine Started an Unusual Process
  description = <<EOT
'An instance of MSBuild, the Microsoft Build Engine, started a PowerShell script or the Visual C# Command Line Compiler. This technique is sometimes used to deploy a malicious payload using the Build Engine.'

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
