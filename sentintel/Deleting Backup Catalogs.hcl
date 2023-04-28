resource "my_alert_rule" "rule_16" {
  name = "Deleting Backup Catalogs"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
let SE = (SecurityEvent
| where Channel == "Security"
| where AccountType == "User"
| where EventID  == "4688"
| where CommandLine has "wbadmin" and  CommandLine  has "delete"
| extend AccountCustomEntity = Account 
| extend HostCustomEntity = Computer
);
let Dfe = (DeviceProcessEvents
| where ProcessCommandLine has "wbadmin" and ProcessCommandLine has "delete" 
| where ActionType == "ProcessCreated"
| extend AccountCustomEntity = AccountName 
| extend HostCustomEntity = DeviceName
| extend CommandLine = ProcessCommandLine
);
SE
| union Dfe
| where not (CommandLine has_any ("wbadmin"))
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = CommandLine
    }
  }
  tactics = ['DefenseEvasion', 'Impact']
  techniques = ['T1562', 'T1490']
  display_name = Deleting Backup Catalogs
  description = <<EOT
'Identifies use of the wbadmin.exe to delete the backup catalog. Ransomware and other malware may do this to prevent system recovery.'

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
