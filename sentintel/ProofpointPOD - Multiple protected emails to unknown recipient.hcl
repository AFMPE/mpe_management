resource "my_alert_rule" "rule_264" {
  name = "ProofpointPOD - Multiple protected emails to unknown recipient"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT30M
  query_period = PT30M
  severity = Medium
  query = <<EOF
let lbtime = 30m;
let lbperiod = 14d;
let knownrecipients = ProofpointPOD
| where TimeGenerated > ago(lbperiod)
| where EventType == 'message'
| where NetworkDirection == 'outbound'
| where SrcUserUpn != ''
| where array_length(todynamic(DstUserUpn)) == 1
| summarize recipients = make_set(tostring(todynamic(DstUserUpn)[0])) by SrcUserUpn
| extend commcol = SrcUserUpn;
ProofpointPOD
| where TimeGenerated between (ago(lbtime) .. now())
| where EventType == 'message'
| where NetworkDirection == 'outbound'
| extend isProtected = todynamic(MsgParts)[0]['isProtected']
| extend mimePgp = todynamic(MsgParts)[0]['detectedMime']
| where isProtected == 'true' or mimePgp == 'application/pgp-encrypted'
| extend DstUserMail = tostring(todynamic(DstUserUpn)[0])
| extend commcol = tostring(todynamic(DstUserUpn)[0])
| join knownrecipients on commcol
| where recipients !contains DstUserMail
| project SrcUserUpn, DstUserMail
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
  display_name = ProofpointPOD - Multiple protected emails to unknown recipient
  description = <<EOT
Detects when multiple protected messages where sent to early not seen recipient.
EOT
  enabled = False
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
