resource "my_alert_rule" "rule_44" {
  name = "User Login from Different Countries within 3 hours"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT3H
  query_period = PT3H
  severity = High
  query = <<EOF
let timeframe = ago(3h);
let threshold = 2;
Okta_CL
| where column_ifexists('published_t', now()) >= timeframe
| where eventType_s =~ "user.session.start"
| where outcome_result_s =~ "SUCCESS"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), NumOfCountries = dcount(client_geographicalContext_country_s), IPAddresses = makeset(client_ipAddress_s), Countries = makeset(client_geographicalContext_country_s) by actor_alternateId_s
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
  display_name = User Login from Different Countries within 3 hours
  description = <<EOT
This query searches for successful user logins to the Okta Console from different countries within 3 hours
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
