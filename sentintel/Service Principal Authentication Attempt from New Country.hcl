resource "my_alert_rule" "rule_18" {
  name = "Service Principal Authentication Attempt from New Country"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
let known_locations = (
  AADServicePrincipalSignInLogs
  | where TimeGenerated between(ago(14d)..ago(1d))
  | where ResultType == 0
  | summarize by Location);
  AADServicePrincipalSignInLogs
  | where TimeGenerated > ago(1d)
  | where ResultType != 50126
  | where Location !in (known_locations)
  | extend City = tostring(parse_json(LocationDetails).city)
  | extend State = tostring(parse_json(LocationDetails).state)
  | extend Place = strcat(City, " - ", State)
  | extend Result = strcat(tostring(ResultType), " - ", ResultDescription)
  | summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), make_set(Result), make_set(IPAddress), make_set(Place) by ServicePrincipalName, Location
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = ServicePrincipalName
    }
  }
  tactics = ['InitialAccess']
  techniques = ['T1078']
  display_name = Service Principal Authentication Attempt from New Country
  description = <<EOT
Detects when there is a Service Principal login attempt from a country that has not seen a successful login in the previous 14 days.
  Threat actors may attempt to authenticate with credentials from compromised accounts - monitoring attempts from anomalous locations may help identify these attempts.
  Authentication attempts should be investigated to ensure the activity was legitimate and if there is other similar activity.
  Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts#monitoring-for-failed-unusual-sign-ins
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
