resource "my_alert_rule" "rule_193" {
  name = "AppServices AV Scan Failure"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Informational
  query = <<EOF
let timeframe = ago(1d);
AppServiceAntivirusScanAuditLogs
| where ScanStatus == "Failed"
| extend HostCustomEntity = _ResourceId, timestamp = TimeGenerated
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
  }
  tactics = None
  techniques = None
  display_name = AppServices AV Scan Failure
  description = <<EOT
Identifies if an AV scan fails in Azure App Services.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = None
    group_by_custom_details = None
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
