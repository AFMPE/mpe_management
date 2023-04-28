resource "my_alert_rule" "rule_58" {
  name = "High Number of Urgent Vulnerabilities Detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
let threshold = 10;
QualysHostDetection_CL
| mv-expand todynamic(Detections_s)
| where Detections_s.Severity == "5"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), count() by NetBios_s, IPAddress
| where count_ >= threshold
| extend timestamp = StartTime, HostCustomEntity = NetBios_s, IPCustomEntity = IPAddress
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['InitialAccess']
  techniques = ['T1190']
  display_name = High Number of Urgent Vulnerabilities Detected
  description = <<EOT
This Creates an incident when a host has a high number of Urgent, severity 5, vulnerabilities detected.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
