resource "my_alert_rule" "rule_14" {
  name = "PsExec Network Connection"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Low
  query = <<EOF
DeviceNetworkEvents
| where InitiatingProcessFileName has "PsExec.exe"
| extend AccountCustomEntity = InitiatingProcessAccountUpn, HostCustomEntity = DeviceName
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
  tactics = ['Execution', 'LateralMovement']
  techniques = ['T1021']
  display_name = PsExec Network Connection
  description = <<EOT
'Identifies use of the SysInternals tool PsExec.exe making a network connection. This could be an indication of lateral movement.'

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
