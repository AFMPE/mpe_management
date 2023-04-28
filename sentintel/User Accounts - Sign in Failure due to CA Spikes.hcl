resource "my_alert_rule" "rule_52" {
  name = "User Accounts - Sign in Failure due to CA Spikes"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
let starttime = 14d;
let timeframe = 1d;
let scorethreshold = 3;
let baselinethreshold = 50;
let aadFunc = (tableName:string){
  // Failed Signins attempts with reasoning related to conditional access policies.
  table(tableName)
  | where TimeGenerated between (startofday(ago(starttime))..startofday(now()))
  | where ResultDescription has_any ("conditional access", "CA") or ResultType in (50005, 50131, 53000, 53001, 53002, 52003, 70044)
  | extend UserPrincipalName = tolower(UserPrincipalName)
  | extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
let allSignins = union isfuzzy=true aadSignin, aadNonInt;
let TimeSeriesAlerts = 
allSignins
| make-series DailyCount=count() on TimeGenerated from startofday(ago(starttime)) to startofday(now()) step 1d by UserPrincipalName
| extend (anomalies, score, baseline) = series_decompose_anomalies(DailyCount, scorethreshold, -1, 'linefit')
| mv-expand DailyCount to typeof(double), TimeGenerated to typeof(datetime), anomalies to typeof(double), score to typeof(double), baseline to typeof(long)
// Filtering low count events per baselinethreshold
| where anomalies > 0 and baseline > baselinethreshold
| extend AnomalyHour = TimeGenerated
| project UserPrincipalName, AnomalyHour, TimeGenerated, DailyCount, baseline, anomalies, score;
// Filter the alerts for specified timeframe
TimeSeriesAlerts
| where TimeGenerated > startofday(ago(timeframe))
| join kind=inner ( 
  allSignins
  | where TimeGenerated > startofday(ago(timeframe))
  // create a new column and round to hour
  | extend DateHour = bin(TimeGenerated, 1h)
  | summarize PartialFailedSignins = count(), LatestAnomalyTime = arg_max(TimeGenerated, *) by bin(TimeGenerated, 1h), OperationName, Category, ResultType, ResultDescription, UserPrincipalName, UserDisplayName, AppDisplayName, ClientAppUsed, IPAddress, ResourceDisplayName
) on UserPrincipalName, $left.AnomalyHour == $right.DateHour
| project LatestAnomalyTime, OperationName, Category, UserPrincipalName, UserDisplayName, ResultType, ResultDescription, AppDisplayName, ClientAppUsed, UserAgent, IPAddress, Location, AuthenticationRequirement, ConditionalAccessStatus, ResourceDisplayName, PartialFailedSignins, TotalFailedSignins = DailyCount, baseline, anomalies, score
| extend timestamp = LatestAnomalyTime, IPCustomEntity = IPAddress, AccountCustomEntity = UserPrincipalName
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['InitialAccess']
  techniques = ['T1078']
  display_name = User Accounts - Sign in Failure due to CA Spikes
  description = <<EOT
 Identifies spike in failed sign-ins from user accounts due to conditional access policied.
Spike is determined based on Time series anomaly which will look at historical baseline values.
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts#monitoring-for-failed-unusual-sign-ins
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
