resource "my_alert_rule" "rule_32" {
  name = "Exchange AuditLog disabled"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
OfficeActivity
| where UserType in~ ("Admin","DcAdmin") 
// Only admin or global-admin can disable audit logging
| where Operation =~ "Set-AdminAuditLogConfig" 
| extend AdminAuditLogEnabledValue = tostring(parse_json(tostring(parse_json(tostring(array_slice(parse_json(Parameters),3,3)))[0])).Value)
| where AdminAuditLogEnabledValue =~ "False" 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), OperationCount = count() by Operation, UserType, UserId, ClientIP, ResultStatus, Parameters, AdminAuditLogEnabledValue
| extend timestamp = StartTimeUtc, AccountCustomEntity = UserId, IPCustomEntity = ClientIP
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
  display_name = Exchange AuditLog disabled
  description = <<EOT
Identifies when the exchange audit logging has been disabled which may be an adversary attempt
to evade detection or avoid other defenses.
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
