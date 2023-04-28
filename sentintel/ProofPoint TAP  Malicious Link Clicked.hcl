resource "my_alert_rule" "rule_190" {
  name = "ProofPoint TAP  Malicious Link Clicked"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = High
  query = <<EOF
ProofpointTAPClickPermitted_CL

EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = AadUserId
      column_name = recipient_s
    }
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = url_s
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = clickIP_s
    }
  }
  tactics = ['InitialAccess']
  techniques = ['T1566']
  display_name = ProofPoint TAP - Malicious Link Clicked
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
