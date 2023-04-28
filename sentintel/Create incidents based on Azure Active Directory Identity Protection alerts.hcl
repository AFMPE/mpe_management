resource "my_alert_rule" "rule_7" {
  name = "Create incidents based on Azure Active Directory Identity Protection alerts"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = None
  query_period = None
  severity = None
  query = <<EOF
None
EOF
  display_name = Create incidents based on Azure Active Directory Identity Protection alerts
  description = <<EOT
Create incidents based on all alerts generated in Azure Active Directory Identity Protection
EOT
  enabled = True
  suppression_duration = None
  suppression_enabled = None
  event_grouping = None
}
