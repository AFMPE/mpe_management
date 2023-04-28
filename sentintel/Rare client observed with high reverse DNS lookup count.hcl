resource "my_alert_rule" "rule_130" {
  name = "Rare client observed with high reverse DNS lookup count"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P8D
  severity = Medium
  query = <<EOF
let starttime = 8d;
let endtime = 1d;
let threshold = 10;
DnsEvents 
| where TimeGenerated > ago(endtime)
| where Name contains "in-addr.arpa" 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), dcount(Name) by ClientIP
| where dcount_Name > threshold
| project StartTimeUtc, EndTimeUtc, ClientIP , dcount_Name 
| join kind=leftanti (DnsEvents 
    | where TimeGenerated between(ago(starttime)..ago(endtime))
    | where Name contains "in-addr.arpa" 
    | summarize dcount(Name) by ClientIP, bin(TimeGenerated, 1d)
    | where dcount_Name > threshold
    | project ClientIP , dcount_Name 
) on ClientIP
| extend timestamp = StartTimeUtc, IPCustomEntity = ClientIP
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['Discovery']
  techniques = ['T1046']
  display_name = Rare client observed with high reverse DNS lookup count
  description = <<EOT
Identifies clients with a high reverse DNS counts which could be carrying out reconnaissance or discovery activity.
Alert is generated if the IP performing such reverse DNS lookups was not seen doing so in the preceding 7-day period.
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
