resource "my_alert_rule" "rule_5" {
  name = "Cisco Umbrella - Rare User Agent Detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
let lookBack = 14d;
let timeframe = 1d;
let user_agents_list = Cisco_Umbrella
| where EventType == "proxylogs"
| where TimeGenerated > ago(lookBack) and TimeGenerated < ago(timeframe)
| summarize count() by HttpUserAgentOriginal
| summarize make_list(HttpUserAgentOriginal);
Cisco_Umbrella
| where EventType == "proxylogs"
| where TimeGenerated > ago(timeframe)
| where HttpUserAgentOriginal !in (user_agents_list)
| extend Message = "Rare User Agent"
| project Message, SrcIpAddr, DstIpAddr, UrlOriginal, TimeGenerated, HttpUserAgentOriginal, DvcAction, HttpRequestMethod, HttpStatusCode
| extend IPCustomEntity = SrcIpAddr, UrlCustomEntity = UrlOriginal
EOF
  entity_mapping {
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = UrlCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['DefenseEvasion']
  techniques = ['T1531']
  display_name = Cisco Umbrella - Rare User Agent Detected
  description = <<EOT
Rule helps to detect a rare user-agents indicating web browsing activity by an unusual process other than a web browser.
EOT
  enabled = True
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
