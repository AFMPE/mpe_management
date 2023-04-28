resource "my_alert_rule" "rule_219" {
  name = "Sharing Policy was Changed (via office365)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
OfficeActivity 
| where (Operation == "SharingPolicyChanged")
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
  tactics = ['DefenseEvasion']
  techniques = ['T1078']
  display_name = Sharing Policy was Changed (via office365)
  description = <<EOT
A SharePoint or global administrator changed a SharePoint sharing policy by using the Office 365 admin portal, SharePoint admin portal, or SharePoint Online Management Shell. Technique: T1078.
EOT
  enabled = False
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
