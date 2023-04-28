resource "my_alert_rule" "rule_55" {
  name = "High Urgency Cyberpion Action Items"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = High
  query = <<EOF
let timeframe = 14d;
let time_generated_bucket = 1h;
let min_urgency = 9;
let maxTimeGeneratedBucket = toscalar(
   CyberpionActionItems_CL
   | where TimeGenerated > ago(timeframe)
   | summarize max(bin(TimeGenerated, time_generated_bucket))
   );
CyberpionActionItems_CL
 | where TimeGenerated > ago(timeframe) and is_open_b == true
 | where bin(TimeGenerated, time_generated_bucket) == maxTimeGeneratedBucket
 | where urgency_d >= min_urgency
 | extend timestamp = opening_datetime_t
 | extend DNSCustomEntity = host_s
EOF
  entity_mapping {
    entity_type = DNS
    field_mappings {
      identifier = DomainName
      column_name = DNSCustomEntity
    }
  }
  tactics = ['InitialAccess']
  techniques = ['T1190', 'T1195']
  display_name = High Urgency Cyberpion Action Items
  description = <<EOT
This query creates an alert for active Cyberpion Action Items with high urgency (9-10).
 Urgency can be altered using the "min_urgency" variable in the query.
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
