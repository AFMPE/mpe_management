resource "my_alert_rule" "rule_119" {
  name = "Suspicious Threat Protection Changes (via office365)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5H
  query_period = PT5H
  severity = High
  query = <<EOF
OfficeActivity 
| where (Operation == "Disable-AntiPhishRule" or Operation == "Disable-SafeAttachmentRule" or Operation == "Disable-SafeLinksRule" or Operation == "Remove-AntiPhishPolicy" or Operation == "Remove-AntiPhishRule" or Operation == "Remove-SafeAttachmentPolicy" or Operation == "Remove-SafeAttachmentRule" or Operation == "Remove-SafeLinksPolicy" or Operation == "Remove-SafeLinksRule")
| extend AccountCustomEntity = UserId, IPCustomEntity = ClientIP
| project AccountCustomEntity, IPCustomEntity, Operation
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
  tactics = ['DefenseEvasion']
  techniques = ['T1562']
  display_name = Suspicious Threat Protection Changes (via office365)
  description = <<EOT
Adversaries may disable security solutions to avoid possible detection of their activities. Technique: T1078.
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
