resource "my_alert_rule" "rule_31" {
  name = "Palo Alto - potential beaconing detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let starttime = 2d;
let endtime = 1d;
let TimeDeltaThreshold = 25;
let TotalEventsThreshold = 30;
let MostFrequentTimeDeltaThreshold = 25;
let PercentBeaconThreshold = 80;
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks" and Activity == "TRAFFIC"
| where TimeGenerated between (startofday(ago(starttime))..startofday(ago(endtime)))
| where ipv4_is_private(DestinationIP)== false
| project TimeGenerated, DeviceName, SourceUserID, SourceIP, SourcePort, DestinationIP, DestinationPort, ReceivedBytes, SentBytes
| sort by SourceIP asc,TimeGenerated asc, DestinationIP asc, DestinationPort asc
| serialize
| extend nextTimeGenerated = next(TimeGenerated, 1), nextSourceIP = next(SourceIP, 1)
| extend TimeDeltainSeconds = datetime_diff('second',nextTimeGenerated,TimeGenerated)
| where SourceIP == nextSourceIP
//Whitelisting criteria/ threshold criteria
| where TimeDeltainSeconds > TimeDeltaThreshold 
| summarize count(), sum(ReceivedBytes), sum(SentBytes)
by TimeDeltainSeconds, bin(TimeGenerated, 1h), DeviceName, SourceUserID, SourceIP, DestinationIP, DestinationPort
| summarize (MostFrequentTimeDeltaCount, MostFrequentTimeDeltainSeconds) = arg_max(count_, TimeDeltainSeconds), TotalEvents=sum(count_), TotalSentBytes = sum(sum_SentBytes), TotalReceivedBytes = sum(sum_ReceivedBytes) 
by bin(TimeGenerated, 1h), DeviceName, SourceUserID, SourceIP, DestinationIP, DestinationPort
| where TotalEvents > TotalEventsThreshold and MostFrequentTimeDeltaCount > MostFrequentTimeDeltaThreshold
| extend BeaconPercent = MostFrequentTimeDeltaCount/toreal(TotalEvents) * 100
| where BeaconPercent > PercentBeaconThreshold
| extend timestamp = TimeGenerated, IPCustomEntity = DestinationIP, AccountCustomEntity = SourceUserID, HostCustomEntity = DeviceName
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
  tactics = ['CommandAndControl']
  techniques = ['T1071', 'T1571']
  display_name = Palo Alto - potential beaconing detected
  description = <<EOT
Identifies beaconing patterns from Palo Alto Network traffic logs based on recurrent timedelta patterns. 
The query leverages various KQL functions to calculate time deltas and then compares it with total events observed in a day to find percentage of beaconing. 
This outbound beaconing pattern to untrusted public networks should be investigated for any malware callbacks or data exfiltration attempts.
Reference Blog:
http://www.austintaylor.io/detect/beaconing/intrusion/detection/system/command/control/flare/elastic/stack/2017/06/10/detect-beaconing-with-flare-elasticsearch-and-intrusion-detection-systems/
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
