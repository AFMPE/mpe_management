resource "my_alert_rule" "rule_359" {
  name = "ProofpointPOD - Possible data exfiltration to private email"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT10M
  query_period = PT10M
  severity = Medium
  query = <<EOF
let lbtime = 10m;
ProofpointPOD
| where TimeGenerated > ago(lbtime)
| where EventType == 'message'
| where NetworkDirection == 'outbound'
| where array_length(todynamic(DstUserUpn)) == 1
| extend sender = extract(@'\A(.*?)@', 1, SrcUserUpn)
| extend sender_domain = extract(@'@(.*)$', 1, SrcUserUpn)
| extend recipient = extract(@'\A(.*?)@', 1, tostring(todynamic(DstUserUpn)[0]))
| extend recipient_domain = extract(@'@(.*)$', 1, tostring(todynamic(DstUserUpn)[0]))
| where sender =~ recipient
| where sender_domain != recipient_domain
| project SrcUserUpn, DstUserUpn
| extend AccountCustomEntity = SrcUserUpn
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
  }
  tactics = ['Exfiltration']
  techniques = ['T1567']
  display_name = ProofpointPOD - Possible data exfiltration to private email
  description = <<EOT
Detects when sender sent email to the non-corporate domain and recipient's username is the same as sender's username.
EOT
  enabled = False
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
