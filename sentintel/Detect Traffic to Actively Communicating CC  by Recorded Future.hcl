resource "my_alert_rule" "rule_277" {
  name = "Detect Traffic to Actively Communicating CC  by Recorded Future"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
let dt_lookBack = 1d;
let ioc_lookBack = 1d;
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| where Active == true
| where Description contains 'Recorded Future'
| where ConfidenceScore >= 65
| join (
    CommonSecurityLog
    | where TimeGenerated >= ago(dt_lookBack)
    )
    on $left.NetworkIP == $right.DestinationIP
| project Description, ThreatType, NetworkIP, ConfidenceScore, AdditionalInformation
| extend IPCustomEntity = NetworkIP
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['CommandAndControl']
  techniques = ['T1571']
  display_name = Detect Traffic to Actively Communicating C&C - by Recorded Future
  description = <<EOT
Recorded Future correlation
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
