resource "my_alert_rule" "rule_87" {
  name = "PulseConnectSecure - Potential Brute Force Attempts"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Low
  query = <<EOF
let threshold = 20;
PulseConnectSecure
| where Messages contains "Login failed"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), count() by User, Source_IP
| where count_ > threshold
| extend timestamp = StartTime, AccountCustomEntity = User, IPCustomEntity = Source_IP
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
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = PulseConnectSecure - Potential Brute Force Attempts
  description = <<EOT
This query identifies evidence of potential brute force attack by looking at multiple failed attempts to log into the VPN server
EOT
  enabled = True
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
