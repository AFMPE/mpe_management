resource "my_alert_rule" "rule_105" {
  name = "Volume Shadow Copy Deletion via WMIC"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = High
  query = <<EOF
let SE = (SecurityEvent 
| where EventID == 4688 and Process == "WMIC.exe" and CommandLine has_all ("shadowcopy","delete")
| project TimeGenerated, Computer, Account, CommandLine);
let DPE = (DeviceProcessEvents
| where FileName has "WMIC.exe" and ProcessCommandLine has_all ("shadowcopy","delete")
| project TimeGenerated, Computer = DeviceName, Account = AccountName, CommandLine = ProcessCommandLine);
SE
| union DPE
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
      column_name = CommandLine
    }
  }
  tactics = ['Impact']
  techniques = ['T1490']
  display_name = Volume Shadow Copy Deletion via WMIC
  description = <<EOT
'Identifies use of whoami.exe which displays user, group, and privileges information for the user who is currently logged on to the local system.'

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
