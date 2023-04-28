resource "my_alert_rule" "rule_215" {
  name = "Suspicious PSModule Path Modification Via cmd"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
DeviceProcessEvents
| where ((ProcessCommandLine has "SetEnvironmentVariable" and ProcessCommandLine has "PSModulePath") or (ProcessCommandLine has "env:PSModulePath" and ProcessCommandLine contains "="))
| extend AccountCustomEntity=AccountName, HostCustomEntity=DeviceName
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
  techniques = ['T1059']
  display_name = Suspicious PSModule Path Modification Via cmd
  description = <<EOT
'Suspicious PSModule Path Modification Via cmd'

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
