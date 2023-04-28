resource "my_alert_rule" "rule_49" {
  name = "Multiple Account Lockouts from Same IP Source"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P3D
  severity = Medium
  query = <<EOF
SecurityEvent
| where EventID == "4740"
| extend Time = bin(TimeCollected, 1m)
| project TimeGenerated, Account, LockoutDC = Computer, Time
| join kind=inner (SecurityEvent
| where EventID == "4625"
| extend Time = bin(TimeCollected, 1m))
on $left.Account == $right.Account and $left.Time == $right.Time
| project TimeGenerated, Account, LockoutDC, IpAddress, LogonFailureDevice = Computer
| where not(IpAddress has_any ("-", "::1"))
| summarize Accounts = make_set(Account) by IpAddress
| where array_length(Accounts) > 1
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IpAddress
    }
  }
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = Multiple Account Lockouts from Same IP Source
  description = <<EOT
This rule correlates multiple account lockouts from the same source IP.
EOT
  enabled = True
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
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
