resource "my_alert_rule" "rule_299" {
  name = "Kubernetes Suspicious Container Activity"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT4H
  severity = High
  query = <<EOF
sysdig_CL
| where proc_pname_s contains "runc" and falco_rule_s == "Terminal shell in container"
| extend AccountCustomEntity = ka_user_name_s
| extend HostCustomEntity = host_hostName_s
| extend IPCustomEntity = host_ip_private_s
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['Execution']
  techniques = ['T1553']
  display_name = Kubernetes Suspicious Container Activity
  description = <<EOT
Identified suspicious container-related activity for Conquestcyber namespaces as high (execs into containers, etc)
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
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
