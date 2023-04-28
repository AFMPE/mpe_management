resource "my_alert_rule" "rule_177" {
  name = "TransportRule Operations (via office365)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5H
  query_period = PT5H
  severity = Medium
  query = <<EOF
OfficeActivity 
| where ((ResultStatus == "True") and (Operation == "Set-TransportRule" or Operation == "Enable-TransportRule")) 
| project Account=UserId, IP=ClientIP, Server=OriginatingServer, Notification=OfficeObjectId, Organization=OrganizationName
//to see more data remove project column
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = Account
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IP
    }
  }
  tactics = ['Exfiltration']
  techniques = ['T1020']
  display_name = TransportRule Operations (via office365)
  description = <<EOT
Create transport rules (mail flow rules) in your organization. Technique: T1020.
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
