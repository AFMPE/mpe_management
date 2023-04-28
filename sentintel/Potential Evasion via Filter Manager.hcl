resource "my_alert_rule" "rule_86" {
  name = "Potential Evasion via Filter Manager"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Low
  query = <<EOF
let SE =
(SecurityEvent 
| where EventID == 4688 and Process == "fltMC.exe" and (CommandLine has_any ("unload","load"))
| extend AccountCustomEntity = Account, HostCustomEntity = Computer)
;
let DPE =
(DeviceProcessEvents
| where FileName has "fltMC.exe" 
| where ProcessCommandLine has_any ("unload","load")
| extend AccountCustomEntity = AccountUpn, HostCustomEntity = DeviceName)
;
SE
| union DPE
| where not(ProcessCommandLine has_any ("BrFilter", "BrCow", "bemk"))
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
  techniques = ['T1205']
  display_name = Potential Evasion via Filter Manager
  description = <<EOT
'The Filter Manager Control Program (fltMC.exe) binary may be abused by adversaries to unload a filter driver and evade defenses.'

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
