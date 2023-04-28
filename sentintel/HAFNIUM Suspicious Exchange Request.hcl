resource "my_alert_rule" "rule_163" {
  name = "HAFNIUM Suspicious Exchange Request"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
let exchange_servers = (
W3CIISLog
| where TimeGenerated > ago(14d)
| where sSiteName =~ "Exchange Back End"
| summarize by Computer);
W3CIISLog
| where TimeGenerated > ago(1d)
| where Computer in (exchange_servers)
| where csUriQuery startswith "t="
| project-reorder TimeGenerated, Computer, csUriStem, csUriQuery, csUserName, csUserAgent, cIP
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
  tactics = ['InitialAccess']
  techniques = ['T1190']
  display_name = HAFNIUM Suspicious Exchange Request
  description = <<EOT
This query looks for suspicious request patterns to Exchange servers that fit a pattern observed by HAFNIUM actors.
The same query can be run on HTTPProxy logs from on-premise hosted Exchange servers.
Reference: https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
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
