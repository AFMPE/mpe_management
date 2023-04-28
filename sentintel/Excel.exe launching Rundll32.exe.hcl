resource "my_alert_rule" "rule_74" {
  name = "Excel.exe launching Rundll32.exe"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = High
  query = <<EOF
let DfE = (DeviceProcessEvents
| where InitiatingProcessFileName has "excel.exe"
| where InitiatingProcessCommandLine contains "rundll32"
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
| project TimeGenerated, HostCustomEntity, AccountCustomEntity, CommandLine = InitiatingProcessCommandLine);
let SE = (SecurityEvent
| where EventID == "4688"
| where ParentProcessName contains "excel.exe"
| where CommandLine contains "rundll32"
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
| project TimeGenerated, HostCustomEntity, AccountCustomEntity, CommandLine);
DfE
| union SE
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
  tactics = ['InitialAccess', 'Execution']
  techniques = ['T1059']
  display_name = Excel.exe launching Rundll32.exe
  description = <<EOT
'Rundll32.exe is used to run DLLs as executable programs. This rule checks for excel.exe creating an instance of rundll32.exe. If EXCEL.EXE spawns a rundll32 process, take note of the the column "NewProcessId". This is the process that could be malicios. Can use KQL to query for actions taken by that process ID, including changing its pid.'

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
