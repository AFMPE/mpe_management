resource "my_alert_rule" "rule_82" {
  name = "Modification of Boot Configuration"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
union
(SecurityEvent
| where Channel == "Security"
| where AccountType == "User"
| where EventID == "4688"
| where Process == "bcdedit.exe"
| where (CommandLine has "set" and CommandLine has "bootstatus") or (CommandLine has "no" and CommandLine has "recoveryenabled")
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
),
(DeviceProcessEvents
| where FileName has "bcdedit"
| where (ProcessCommandLine has "set" and ProcessCommandLine has "bootstatus") or (ProcessCommandLine has "no" and ProcessCommandLine has "recoveryenabled")
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
)
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
  tactics = ['Persistence']
  techniques = ['T1547']
  display_name = Modification of Boot Configuration
  description = <<EOT
'Identifies use of bcdedit.exe to delete boot configuration data. Malware and attackers sometimes use this tactic as a destructive technique.''

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
