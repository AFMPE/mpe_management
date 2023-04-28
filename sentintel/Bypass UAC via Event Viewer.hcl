resource "my_alert_rule" "rule_309" {
  name = "Bypass UAC via Event Viewer"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
let SE = (SecurityEvent
    | where EventID == 4688
    | where ParentProcessName has "eventvwr" and Process !has "mmc.exe"
    | extend HostCustomEntity = Computer, AccounCustomEntity = AccountName, CommandLine
    );
let DfE = (DeviceProcessEvents
    | where InitiatingProcessFileName has "eventvwr.exe" and ProcessCommandLine !has "mmc.exe"
    | extend HostCustomEntity = DeviceName, AccounCustomEntity = AccountUpn, CommandLine = ProcessCommandLine
    );
SE
| union DfE
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = AccounCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = HostCustomEntity
    }
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = CommandLine
    }
  }
  tactics = ['PrivilegeEscalation']
  techniques = ['T1548']
  display_name = Bypass UAC via Event Viewer
  description = <<EOT
'Identifies User Account Control (UAC) bypass via eventvwr.exe. Attackers bypass UAC to stealthily execute code with elevated permissions.'

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
