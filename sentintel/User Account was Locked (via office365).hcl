resource "my_alert_rule" "rule_298" {
  name = "User Account was Locked (via office365)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5H
  query_period = PT5H
  severity = Medium
  query = <<EOF
OfficeActivity 
| where Operation == "UserLoginFailed" | where * contains "IdsLocked"
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = UserId
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = ClientIP
    }
  }
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = User Account was Locked (via office365)
  description = <<EOT
Possible user account brute. Technique: T1110.
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
