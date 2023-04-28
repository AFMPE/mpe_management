resource "my_alert_rule" "rule_153" {
  name = "Potential DGA detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P10D
  severity = Medium
  query = <<EOF
let starttime = 10d;
let endtime = 1d;
let threshold = 100;
let nxDomainDnsEvents = DnsEvents 
| where ResultCode == 3 
| where QueryType in ("A", "AAAA")
| where ipv4_is_match("127.0.0.1", ClientIP) == False
| where Name !contains "/"
| where Name contains ".";
nxDomainDnsEvents
| where TimeGenerated > ago(endtime)
| extend sld = tostring(split(Name, ".")[-2])
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), dcount(sld) by ClientIP
| where dcount_sld > threshold
// Filter out previously seen IPs
| join kind=leftanti (nxDomainDnsEvents
    | where TimeGenerated between(ago(starttime)..ago(endtime))
    | extend sld = tostring(split(Name, ".")[-2])
    | summarize dcount(sld) by ClientIP
    | where dcount_sld > threshold ) on ClientIP
// Pull out sample NXDomain responses for those remaining potentially infected IPs
| join kind = inner (nxDomainDnsEvents | summarize by Name, ClientIP) on ClientIP
| summarize StartTimeUtc = min(StartTimeUtc), EndTimeUtc = max(EndTimeUtc), sampleNXDomainList=make_list(Name, 100)  by ClientIP, dcount_sld
| extend timestamp = StartTimeUtc, IPCustomEntity = ClientIP
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['CommandAndControl']
  techniques = ['T1568', 'T1008']
  display_name = Potential DGA detected
  description = <<EOT
Identifies clients with a high NXDomain count which could be indicative of a DGA (cycling through possible C2 domains
where most C2s are not live). Alert is generated when a new IP address is seen (based on not being seen associated with 
NXDomain records in prior 10-day baseline period).
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
