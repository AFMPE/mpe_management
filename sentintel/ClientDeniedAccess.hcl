resource "my_alert_rule" "rule_346" {
  name = "ClientDeniedAccess"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
let threshold = 15;
let rejectedAccess = SymantecVIP
| where isnotempty(RADIUSAuth)
| where RADIUSAuth =~ "Reject"
| summarize Total = count() by ClientIP, bin(TimeGenerated, 15m)
| where Total > threshold
| project ClientIP;
SymantecVIP
| where isnotempty(RADIUSAuth)
| where RADIUSAuth =~ "Reject"
| join kind=inner rejectedAccess on ClientIP
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), count() by ClientIP, User
| extend timestamp = StartTime, IPCustomEntity = ClientIP, AccountCustomEntity = User
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
  display_name = ClientDeniedAccess
  description = <<EOT
Creates an incident in the event a Client has an excessive amounts of denied access requests.
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
