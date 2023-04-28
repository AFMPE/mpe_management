resource "my_alert_rule" "rule_340" {
  name = "Cisco Umbrella - Empty User Agent Detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT15M
  query_period = PT15M
  severity = Medium
  query = <<EOF
let timeframe = 15m;
Cisco_Umbrella
| where EventType == "proxylogs"
| where TimeGenerated > ago(timeframe)
| where HttpUserAgentOriginal == ''
| extend Message = "Empty User Agent"
| project Message, SrcIpAddr, DstIpAddr, UrlOriginal, TimeGenerated
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
  display_name = Cisco Umbrella - Empty User Agent Detected
  description = <<EOT
Rule helps to detect empty and unusual user agent indicating web browsing activity by an unusual process other than a web browser.
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