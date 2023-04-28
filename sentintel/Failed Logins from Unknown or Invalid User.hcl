resource "my_alert_rule" "rule_183" {
  name = "Failed Logins from Unknown or Invalid User"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
let FailureThreshold = 15;
let FailedLogins = Okta_CL
| where eventType_s =~ "user.session.start" and outcome_reason_s =~ "VERIFICATION_ERROR"
| summarize count() by actor_alternateId_s, client_ipAddress_s, bin(TimeGenerated, 5m)
| where count_ > FailureThreshold
| project client_ipAddress_s, actor_alternateId_s;
Okta_CL
| join kind=inner (FailedLogins) on client_ipAddress_s, actor_alternateId_s
| where eventType_s =~ "user.session.start" and outcome_reason_s =~ "VERIFICATION_ERROR"
| summarize count() by actor_alternateId_s, ClientIP = client_ipAddress_s, City = client_geographicalContext_city_s, Country = client_geographicalContext_country_s, column_ifexists('published_t', now())
| sort by column_ifexists('published_t', now()) desc
| extend timestamp = column_ifexists('published_t', now()), IPCustomEntity = ClientIP, AccountCustomEntity = actor_alternateId_s
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = Failed Logins from Unknown or Invalid User
  description = <<EOT
This query searches for numerous login attempts to the management console with an unknown or invalid user name
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
