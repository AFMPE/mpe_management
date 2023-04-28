resource "my_alert_rule" "rule_20" {
  name = "Perimeter Device No Logs Incoming"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P3D
  severity = High
  query = <<EOF
let activeTime = 3d;
let staleTime = 1h;
CommonSecurityLog
| where TimeGenerated > ago(activeTime)
| summarize LastHeartbeat = max(TimeGenerated) by Computer, DeviceVendor
| where isnotempty(Computer)
| where DeviceVendor !has "TestCommonEventFormat"
| where LastHeartbeat < ago(staleTime)

EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = Computer
    }
  }
  tactics = ['Discovery']
  techniques = ['T1046']
  display_name = Perimeter Device No Logs Incoming
  description = <<EOT
Sentinel has stopped receiving logs from perimeter devices
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
