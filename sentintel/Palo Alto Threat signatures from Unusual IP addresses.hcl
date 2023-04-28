resource "my_alert_rule" "rule_179" {
  name = "Palo Alto Threat signatures from Unusual IP addresses"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P7D
  severity = Medium
  query = <<EOF
let starttime = 7d;
let endtime = 1d;
let timeframe = 1h;
let HistThreshold = 25; 
let CurrThreshold = 10; 
let HistoricalThreats = CommonSecurityLog
| where isnotempty(SourceIP)
| where TimeGenerated between (startofday(ago(starttime))..startofday(ago(endtime)))
| where DeviceVendor =~ "Palo Alto Networks"
| where Activity =~ "THREAT" and SimplifiedDeviceAction =~ "alert" 
| where DeviceEventClassID in ('spyware', 'scan', 'file', 'vulnerability', 'flood', 'packet', 'virus','wildfire', 'wildfire-virus')
| summarize TotalEvents = count(), ThreatTypes = make_set(DeviceEventClassID), DestinationIpList = make_set(DestinationIP), FirstSeen = min(TimeGenerated) , LastSeen = max(TimeGenerated) by SourceIP, DeviceAction, DeviceVendor;
let CurrentHourThreats =  CommonSecurityLog
| where isnotempty(SourceIP)
| where TimeGenerated > ago(timeframe)
| where DeviceVendor =~ "Palo Alto Networks"
| where Activity =~ "THREAT" and SimplifiedDeviceAction =~ "alert" 
| where DeviceEventClassID in ('spyware', 'scan', 'file', 'vulnerability', 'flood', 'packet', 'virus','wildfire', 'wildfire-virus')
| summarize TotalEvents = count(), ThreatTypes = make_set(DeviceEventClassID), DestinationIpList = make_set(DestinationIP), FirstSeen = min(TimeGenerated) , LastSeen = max(TimeGenerated) by SourceIP, DeviceAction, DeviceProduct, DeviceVendor;
CurrentHourThreats 
| where TotalEvents < CurrThreshold
| join kind = leftanti (HistoricalThreats 
| where TotalEvents > HistThreshold) on SourceIP
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = SourceIP
    }
  }
  tactics = ['Discovery', 'Exfiltration', 'CommandAndControl']
  techniques = ['T1046', 'T1030', 'T1071']
  display_name = Palo Alto Threat signatures from Unusual IP addresses
  description = <<EOT
Identifies Palo Alto Threat signatures from unusual IP addresses which are not historically seen. 
This detection is also leveraged and required for MDE and PAN Fusion scenario
https://docs.microsoft.com/Azure/sentinel/fusion-scenario-reference#network-request-to-tor-anonymization-service-followed-by-anomalous-traffic-flagged-by-palo-alto-networks-firewall
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
