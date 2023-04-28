resource "my_alert_rule" "rule_3" {
  name = "AppServices AV Scan with Infected Files"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Informational
  query = <<EOF
let timeframe = ago(1d);
AppServiceAntivirusScanAuditLogs
| where NumberOfInfectedFiles > 0
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
  display_name = AppServices AV Scan with Infected Files
  description = <<EOT
Identifies if an AV scan finds infected files in Azure App Services.
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
