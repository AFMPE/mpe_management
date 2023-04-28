resource "my_alert_rule" "rule_34" {
  name = "Clearing Windows Event Logs"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
union
(SecurityEvent
| where AccountType == "User"
| where Channel == "Security"
| where EventID == "4688"
| where Process == "wevtutil.exe"
| where CommandLine has "cl"
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
),
(DeviceProcessEvents
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has "cl"
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
  tactics = ['DefenseEvasion']
  techniques = ['T1070']
  display_name = Clearing Windows Event Logs
  description = <<EOT
'Identifies attempts to clear Windows event log stores. This is often done by attackers in an attempt to evade detection or destroy forensic evidence on a system.'

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
