resource "my_alert_rule" "rule_186" {
  name = "Winword.exe launching Rundll32.exe"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
let SE = (SecurityEvent
| where EventID == 4688 
| where ParentProcessName has "WINWORD.EXE" and Process == "rundll32.exe" 
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
);
let DfE = (DeviceProcessEvents
| where InitiatingProcessFileName has "WINWORD.EXE" and ProcessCommandLine has "rundll32.exe"
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
);
SE
| union DfE
| where not(ProcessCommandLine has "ndfapi.dll")
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
  display_name = Winword.exe launching Rundll32.exe
  description = <<EOT
'Rundll32.exe is used to run DLLs as executable programs. This rule checks for winword.exe creating an instance of rundll32.exe. If WINWORD.EXE spawns a rundll32 process, take note of the the column "NewProcessId". This is the process that could be malicios. Can use KQL to query for actions taken by that process ID, including changing its pid.'

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
