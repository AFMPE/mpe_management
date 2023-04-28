resource "my_alert_rule" "rule_322" {
  name = "Critical Threat Detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
let threshold = 8;
CarbonBlackNotifications_CL
| where threatHunterInfo_score_d >= threshold
| extend eventTime = datetime(1970-01-01) + tolong(threatHunterInfo_time_d/1000) * 1sec
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), count() by eventTime, Threat_Name = threatHunterInfo_reportName_s, Device_Name = deviceInfo_deviceName_s,  Internal_IP = deviceInfo_internalIpAddress_s, External_IP = deviceInfo_externalIpAddress_s, Threat_Score = threatHunterInfo_score_d
| project-away count_
| extend timestamp = StartTime, HostCustomEntity = Device_Name, IPCustomEntity = Internal_IP
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
  tactics = ['LateralMovement']
  techniques = ['T1210']
  display_name = Critical Threat Detected
  description = <<EOT
This creates an incident in the event a critical threat was identified on a Carbon Black managed endpoint.
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
