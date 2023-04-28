resource "my_alert_rule" "rule_129" {
  name = "Powershell Execution via RunCommand(Azure VM)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
let VmLog = (SecurityEvent | where ParentProcessName has "RunCommandExtension.exe"| extend HostCustomEntity=Computer);
let DVmLog = (DeviceProcessEvents | where InitiatingProcessFileName has "RunCommandExtension.exe"| extend HostCustomEntity = DeviceName);
AzureActivity
| where OperationName == "Run Command on Virtual Machine"
| where ActivityStatus == "Succeeded"
| extend HostCustomEntity=Resource
| union (VmLog),(DVmLog)
| where not(ParentProcessName has_any("packages\\plugins\\microsoft.cplat.core.runcommandwindows\\1.1.11\\bin\\runcommandextension.exe"))
| where not(InitiatingProcessFolderPath has_any("packages\\plugins\\microsoft.cplat.core.runcommandwindows\\1.1.11\\bin\\runcommandextension.exe"))
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = HostCustomEntity
    }
  }
  tactics = ['Execution']
  techniques = ['T1059']
  display_name = Powershell Execution via RunCommand(Azure VM)
  description = <<EOT
'Detects Run Commands as system from azure RunCommand VM feature'

EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = None
    group_by_custom_details = None
  }
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
