resource "my_alert_rule" "rule_317" {
  name = "Cisco Umbrella - Connection to Unpopular Website Detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
let domain_lookBack= 14d;
let timeframe = 1d;
let top_million_list = Cisco_Umbrella
| where EventType == "proxylogs"
| where TimeGenerated > ago(domain_lookBack) and TimeGenerated < ago(timeframe)
| extend Hostname = parse_url(UrlOriginal)["Host"]
| summarize count() by tostring(Hostname)
| top 1000000 by count_
| summarize make_list(Hostname);
Cisco_Umbrella
| where EventType == "proxylogs"
| where TimeGenerated > ago(timeframe)
| extend Hostname = parse_url(UrlOriginal)["Host"]
| where Hostname !in (top_million_list)
| extend Message = "Connect to unpopular website (possible malicious payload delivery)"
| project Message, SrcIpAddr, DstIpAddr,UrlOriginal, TimeGenerated
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
  tactics = ['CommandAndControl']
  techniques = ['T1571']
  display_name = Cisco Umbrella - Connection to Unpopular Website Detected
  description = <<EOT
Detects first connection to an unpopular website (possible malicious payload delivery).
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
