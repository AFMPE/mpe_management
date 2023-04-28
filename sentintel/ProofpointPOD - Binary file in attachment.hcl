resource "my_alert_rule" "rule_12" {
  name = "ProofpointPOD - Binary file in attachment"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT10M
  query_period = PT10M
  severity = Medium
  query = <<EOF
let lbtime = 10m;
ProofpointPOD
| where TimeGenerated > ago(lbtime)
| where EventType == 'message'
| where NetworkDirection == 'inbound'
| where FilterDisposition !in ('reject', 'discard')
| extend attachedMimeType = todynamic(MsgParts)[0]['detectedMime']
| where attachedMimeType == 'application/zip'
| project SrcUserUpn, DstUserUpn
| extend AccountCustomEntity = DstUserUpn
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
  display_name = ProofpointPOD - Binary file in attachment
  description = <<EOT
Detects when email recieved with binary file as attachment.
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
