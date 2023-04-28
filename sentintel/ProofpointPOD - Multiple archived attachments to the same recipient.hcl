resource "my_alert_rule" "rule_377" {
  name = "ProofpointPOD - Multiple archived attachments to the same recipient"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT30M
  query_period = PT30M
  severity = Medium
  query = <<EOF
let lbtime = 30m;
let msgthreshold = 3;
ProofpointPOD
| where TimeGenerated > ago(lbtime)
| where EventType == 'message'
| where NetworkDirection == 'outbound'
| extend attachedMimeType = todynamic(MsgParts)[0]['detectedMime']
| where attachedMimeType == 'application/zip'
| summarize count() by SrcUserUpn, DstUserUpn
| where count_ > msgthreshold
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
  display_name = ProofpointPOD - Multiple archived attachments to the same recipient
  description = <<EOT
Detects when multiple emails where sent to the same recipient with large archived attachments.
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
