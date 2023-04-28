resource "my_alert_rule" "rule_245" {
  name = "Impossible Travel Detected in Okta Logs"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT3H
  query_period = PT3H
  severity = Medium
  query = <<EOF
let timeframe = ago(3h);
let threshold = 2;
Okta_CL
| where TimeGenerated >= timeframe
| where eventType_s =~ "user.session.start"
| where outcome_result_s =~ "SUCCESS"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), NumOfCountries = dcount(client_geographicalContext_country_s), makeset(client_geographicalContext_country_s), makeset(client_ipAddress_s), makeset(client_device_s) by actor_alternateId_s
| where NumOfCountries >= threshold
| extend timestamp = StartTime, AccountCustomEntity = actor_alternateId_s
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
  }
  tactics = ['InitialAccess']
  techniques = ['T1078']
  display_name = Impossible Travel Detected in Okta Logs
  description = <<EOT

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
