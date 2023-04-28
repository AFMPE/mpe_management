resource "my_alert_rule" "rule_167" {
  name = "Proxy Token Activity"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
W3CIISLog
| where (scStatus == "500" and csUriStem contains '/ecp/' and ((csMethod =~ 'POST' and csUriStem contains '/RulesEditor/InboxRules.svc/NewObject') or csUriStem contains 'SecurityToken='))
| extend timestamp = TimeGenerated, AccountCustomEntity = csUserName, HostCustomEntity = Computer, IPCustomEntity = cIP
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['InitialAccess', 'DefenseEvasion']
  techniques = ['T1204']
  display_name = Proxy Token Activity
  description = <<EOT
This rule detects IOCs of ProxyToken
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
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
