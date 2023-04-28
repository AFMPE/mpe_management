resource "my_alert_rule" "rule_296" {
  name = "ProofpointPOD - Weak ciphers"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Low
  query = <<EOF
let lbtime = 1h;
let tls_ciphers = dynamic(['RC4-SHA', 'DES-CBC3-SHA']);
ProofpointPOD
| where EventType == 'message'
| where TlsCipher in (tls_ciphers)
| extend IpCustomEntity = SrcIpAddr
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = None
  techniques = None
  display_name = ProofpointPOD - Weak ciphers
  description = <<EOT
Detects when weak TLS ciphers are used.
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
