resource "my_alert_rule" "rule_337" {
  name = "Falco Alert"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
FalcoLogs_CL
| where priority_s has_any ("critical")
//| where priority_s has_any ("emergency", "alert", "critical")
| project TimeGenerated, AlertName = rule_s, HostName = kubernetes_host_s, IPAddress = kubernetes_pod_ip_s
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = HostName
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPAddress
    }
  }
  tactics = ['Execution', 'PrivilegeEscalation']
  techniques = ['T1059', 'T1134']
  display_name = Falco Alert
  description = <<EOT
Falco Alert
EOT
  enabled = False
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
