resource "my_alert_rule" "rule_261" {
  name = "Powershell Encoded Command Alias Detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
let SE =(SecurityEvent
| where EventID == "4688"
| where CommandLine has_any(" -ea", " -ec")
| extend AccountCustomEntity = Account, HostCustomEntity = Computer);
let DPE =(DeviceProcessEvents
| where (InitiatingProcessCommandLine has_any (" -ea", " -ec") or ProcessCommandLine has_any (" -ea", " -ec")) 
| where not (MachineGroup has_any ("MacOS Devices Group"))
| extend AccountCustomEntity = AccountUpn, HostCustomEntity = DeviceName);
SE
|union DPE
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
  tactics = ['Execution']
  techniques = ['T1059']
  display_name = Powershell Encoded Command Alias Detected
  description = <<EOT
'Powershell Encoded Command Alias Detection, This technique is used to bypass Detection via Alias usages'

EOT
  enabled = False
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
