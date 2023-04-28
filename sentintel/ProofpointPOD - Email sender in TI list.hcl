resource "my_alert_rule" "rule_368" {
  name = "ProofpointPOD - Email sender in TI list"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now() 
| where Active == true
| where isnotempty(EmailSenderAddress)
| extend TI_emailEntity = EmailSenderAddress
// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated
| join kind=innerunique (
       ProofpointPOD 
       | where TimeGenerated >= ago(dt_lookBack)
       | where isnotempty(SrcUserUpn)
       | extend ProofpointPOD_TimeGenerated = TimeGenerated, ClientEmail = SrcUserUpn
          
)
on $left.TI_emailEntity == $right.ClientEmail
| where ProofpointPOD_TimeGenerated < ExpirationDateTime
| summarize ProofpointPOD_TimeGenerated = arg_max(ProofpointPOD_TimeGenerated, *) by IndicatorId, ClientEmail
| project ProofpointPOD_TimeGenerated, Description, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, ClientEmail
| extend timestamp = ProofpointPOD_TimeGenerated
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = ClientEmail
    }
  }
  tactics = ['Exfiltration', 'InitialAccess']
  techniques = ['T1078', 'T1567']
  display_name = ProofpointPOD - Email sender in TI list
  description = <<EOT
Email sender in TI list.
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
