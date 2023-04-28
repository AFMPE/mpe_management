resource "my_alert_rule" "rule_284" {
  name = "Recorded Future Similar Domains"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5H
  query_period = PT5H
  severity = Low
  query = <<EOF
RF_Typosquat_CL
EOF
  entity_mapping {
    entity_type = DNS
    field_mappings {
      identifier = DomainName
      column_name = Domain_s
    }
  }
  tactics = ['ResourceDevelopment']
  techniques = ['T1583']
  display_name = Recorded Future - Similar Domains
  description = <<EOT

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
