resource "my_alert_rule" "rule_272" {
  name = "Possible Cobalt Strike payload delivery via WMI"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = High
  query = <<EOF
let SE = (SecurityEvent
| where ParentProcessName contains "WmiPrvSE.exe" and CommandLine contains "powershell.exe" and (CommandLine contains "Value" or CommandLine contains "env" or CommandLine contains "IE" or CommandLine contains "-w hidden -encodedcommand")
| extend AccountCustomEntity = Account, HostCustomEntity = Computer);
let DPE = (DeviceProcessEvents
| where InitiatingProcessFileName has "WmiPrvSE.exe" and ProcessCommandLine has "powershell.exe" and (ProcessCommandLine has_any ("Value","env","IE","-w hidden -encodedcommand"))
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName, CommandLine = ProcessCommandLine);
SE
| union DPE
| where not(CommandLine has_any ("nessus", "ROOT\\ccm\\ClientSDK:CCM_SoftwareUpdatesManager", "nessus_cmd"))
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
  techniques = ['T1047']
  display_name = Possible Cobalt Strike payload delivery via WMI
  description = <<EOT
'Cobalt Strike can use PowerShell to bootstrap a payload on target'

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
