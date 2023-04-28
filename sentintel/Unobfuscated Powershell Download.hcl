resource "my_alert_rule" "rule_347" {
  name = "Unobfuscated Powershell Download"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = High
  query = <<EOF
let SE = (SecurityEvent
| where AccountType == "User"
| where Channel == "Security"
| where Process has "powershell.exe"
| where CommandLine has_any ("downloadString","downloadFile")
| project TimeGenerated, Computer, Account, CommandLine, Activity);
let DPE = (DeviceProcessEvents
| where FileName has "powershell.exe"
| where ProcessCommandLine has_any ("downloadString", "downloadFile")
| project-rename Computer=DeviceName, Account=AccountName, CommandLine=ProcessCommandLine, GrandParentProcess=InitiatingProcessParentFileName);
SE
| union DPE
| where not (CommandLine has_any ("Webex\\Plugins\\ptUpdate.exe", "HumanResources\\HumanResources\\DownloadFiles.dtsx","node.exe", "WaAgent", "169.254"))
| where not (CommandLine contains "metadata/latest/Instance" or CommandLine contains "/metadata/instance")
| where not (InitiatingProcessCommandLine has_any ("WaAgent", "metadata//latest//InstanceInfo", "metadata//instance//compute"))

EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = Account
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = Computer
    }
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = GrandParentProcess
    }
  }
  tactics = ['Execution']
  techniques = ['T1059']
  display_name = Unobfuscated Powershell Download
  description = <<EOT
'Detecs CommandLine Parameter when downloading code/payload via powershell'

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
