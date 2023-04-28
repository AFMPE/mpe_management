resource "my_alert_rule" "rule_10" {
  name = "Possible Payload Delivery via WMI cobalt strike"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
union(SecurityEvent
| where ParentProcessName has "WmiPrvSE.exe"
| where Process == "powershell.exe"
| where CommandLine has_any ("Value", "env", "IE", "-w hidden -encodedcommand")
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
),
(DeviceProcessEvents
| where InitiatingProcessFileName == "WmiPrvSE.exe"
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any ("Value", "env", "IE", "-w hidden -encodedcommand")
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
  tactics = ['Execution', 'DefenseEvasion']
  techniques = ['T1047']
  display_name = Possible Payload Delivery via WMI cobalt strike
  description = <<EOT
'Detects Possible Payload Delivery via WMI cobalt strike'

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
