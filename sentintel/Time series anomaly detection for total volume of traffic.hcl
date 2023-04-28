resource "my_alert_rule" "rule_231" {
  name = "Time series anomaly detection for total volume of traffic"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
let starttime = 14d;
let endtime = 1d;
let timeframe = 1h;
let scorethreshold = 5;
let percentotalthreshold = 50;
let TimeSeriesData = CommonSecurityLog
| where isnotempty(DestinationIP) and isnotempty(SourceIP)
| where TimeGenerated between (startofday(ago(starttime))..startofday(ago(endtime)))
| project TimeGenerated,SourceIP, DestinationIP, DeviceVendor
| make-series Total=count() on TimeGenerated from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe by DeviceVendor;
// Filtering specific records associated with spikes as outliers
let TimeSeriesAlerts=materialize(TimeSeriesData
| extend (anomalies, score, baseline) = series_decompose_anomalies(Total, scorethreshold, -1, 'linefit')
| mv-expand Total to typeof(double), TimeGenerated to typeof(datetime), anomalies to typeof(double),score to typeof(double), baseline to typeof(long)
| where anomalies > 0 | extend score = round(score,2), AnomalyHour = TimeGenerated
| project DeviceVendor,AnomalyHour, TimeGenerated, Total, baseline, anomalies, score);
let AnomalyHours = materialize(TimeSeriesAlerts  | where TimeGenerated > ago(2d) | project TimeGenerated);
// Join anomalies with Base Data to popalate associated records for investigation - Results sorted by score in descending order
TimeSeriesAlerts
| where TimeGenerated > ago(2d)
| join (
    CommonSecurityLog
| where isnotempty(DestinationIP) and isnotempty(SourceIP)
| where TimeGenerated > ago(2d)
| extend DateHour = bin(TimeGenerated, 1h) // create a new column and round to hour
| where DateHour in ((AnomalyHours)) //filter the dataset to only selected anomaly hours
| summarize HourlyCount = count(), TimeGeneratedMax = arg_max(TimeGenerated, *), DestinationIPlist = make_set(DestinationIP, 100), DestinationPortlist = make_set(DestinationPort, 100) by DeviceVendor, SourceIP, TimeGeneratedHour= bin(TimeGenerated, 1h)
| extend AnomalyHour = TimeGeneratedHour
) on AnomalyHour, DeviceVendor
| extend PercentTotal = round((HourlyCount / Total) * 100, 3)
| where PercentTotal > percentotalthreshold
| project DeviceVendor , AnomalyHour, TimeGeneratedMax, SourceIP, DestinationIPlist, DestinationPortlist, HourlyCount, PercentTotal, Total, baseline, score, anomalies
| summarize HourlyCount=sum(HourlyCount), StartTimeUtc=min(TimeGeneratedMax), EndTimeUtc=max(TimeGeneratedMax), SourceIPlist = make_set(SourceIP, 100), SourceIPMax= arg_max(SourceIP, *), DestinationIPlist = make_set(DestinationIPlist, 100), DestinationPortlist = make_set(DestinationPortlist, 100) by DeviceVendor , AnomalyHour, Total, baseline, score, anomalies
| project DeviceVendor , AnomalyHour, EndTimeUtc, SourceIPMax ,SourceIPlist, DestinationIPlist, DestinationPortlist, HourlyCount, Total, baseline, score, anomalies
| extend timestamp= EndTimeUtc , IPCustomEntity = SourceIPMax
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['Exfiltration']
  techniques = ['T1030']
  display_name = Time series anomaly detection for total volume of traffic
  description = <<EOT
Identifies anamalous spikes in network traffic logs as compared to baseline or normal historical patterns.
The query leverages a KQL built-in anomaly detection algorithm to find large deviations from baseline patterns.
Sudden increases in network traffic volume may be an indication of data exfiltration attempts and should be investigated.
The higher the score, the further it is from the baseline value.
The output is aggregated to provide summary view of unique source IP to destination IP address and port traffic observed in the flagged anomaly hour.
The source IP addresses which were sending less than percentotalthreshold of the total traffic have been exluded whose value can be adjusted as needed .
You may have to run queries for individual source IP addresses from SourceIPlist to determine if anything looks suspicious
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
