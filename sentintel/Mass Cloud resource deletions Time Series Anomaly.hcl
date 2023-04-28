resource "my_alert_rule" "rule_358" {
  name = "Mass Cloud resource deletions Time Series Anomaly"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
let starttime = 14d;
let endtime = 1d;
let timeframe = 1h;
let TotalEventsThreshold = 25; 
let TimeSeriesData = 
AzureActivity 
| where TimeGenerated between (startofday(ago(starttime))..startofday(ago(endtime)))
| where OperationNameValue endswith "delete" 
| project TimeGenerated, Caller 
| make-series Total = count() on TimeGenerated from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe by Caller; 
let TimeSeriesAlerts = materialize(TimeSeriesData 
| extend (anomalies, score, baseline) = series_decompose_anomalies(Total, 3, -1, 'linefit') 
| mv-expand Total to typeof(double), TimeGenerated to typeof(datetime), anomalies to typeof(double), score to typeof(double), baseline to typeof(long) 
| where anomalies > 0 
| project Caller, TimeGenerated, Total, baseline, anomalies, score 
| where Total > TotalEventsThreshold and baseline > 0 ); 
TimeSeriesAlerts 
| where TimeGenerated > (ago(endtime)) 
| project TimeGenerated, Caller 
| join (AzureActivity 
| where TimeGenerated > (ago(endtime)) 
| where OperationNameValue endswith "delete" 
| summarize count(), make_set(OperationNameValue), make_set(Resource) by bin(TimeGenerated, 1h), Caller) on TimeGenerated, Caller 
| extend timestamp = TimeGenerated, AccountCustomEntity = Caller
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = ['T1485']
  display_name = Mass Cloud resource deletions Time Series Anomaly
  description = <<EOT
This query generates baseline pattern of cloud resource deletions by an user and generated anomaly 
when any unusual spike is detected.
These anomalies from unusual or privileged users could be an indication of cloud infrastructure 
take-down by an adversary 
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
