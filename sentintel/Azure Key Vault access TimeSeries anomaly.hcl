resource "my_alert_rule" "rule_216" {
  name = "Azure Key Vault access TimeSeries anomaly"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Low
  query = <<EOF
let starttime = 14d;
let timeframe = 1d;
let scorethreshold = 3;
let baselinethreshold = 5;
let OperationList = dynamic(
["SecretGet", "KeyGet", "VaultGet"]);
let TimeSeriesData = AzureDiagnostics
| where TimeGenerated between (startofday(ago(starttime))..startofday(now()))
| extend ResultType = columnifexists("ResultType", "None"), CallerIPAddress = columnifexists("CallerIPAddress", "None")
| where ResultType !~ "None" and isnotempty(ResultType)
| where CallerIPAddress !~ "None" and isnotempty(CallerIPAddress)
| where ResourceType =~ "VAULTS" and ResultType =~ "Success"
| where OperationName in (OperationList)
| project TimeGenerated, OperationName, Resource, CallerIPAddress
| make-series HourlyCount=count() on TimeGenerated from startofday(ago(starttime)) to startofday(now()) step timeframe by Resource;
//Filter anomolies against TimeSeriesData
let TimeSeriesAlerts = TimeSeriesData
| extend (anomalies, score, baseline) = series_decompose_anomalies(HourlyCount, scorethreshold, -1, 'linefit')
| mv-expand HourlyCount to typeof(double), TimeGenerated to typeof(datetime), anomalies to typeof(double),score to typeof(double), baseline to typeof(long)
| where anomalies > 0 | extend AnomalyHour = TimeGenerated
| where baseline > baselinethreshold // Filtering low count events per baselinethreshold
| project Resource, AnomalyHour, TimeGenerated, HourlyCount, baseline, anomalies, score;
let AnomalyHours = TimeSeriesAlerts | where TimeGenerated > ago(2d) | project TimeGenerated;
// Filter the alerts since specified timeframe
TimeSeriesAlerts
| where TimeGenerated > ago(2d)
// Join against base logs since specified timeframe to retrive records associated with the hour of anomoly
| join (
AzureDiagnostics
| where TimeGenerated > ago(timeframe)
| extend DateHour = bin(TimeGenerated, 1h) // create a new column and round to hour
| where DateHour in ((AnomalyHours)) //filter the dataset to only selected anomaly hours
| extend ResultType = columnifexists("ResultType", "NoResultType")
| extend requestUri_s = columnifexists("requestUri_s", "None"), identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g = columnifexists("identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g", "None")
| extend id_s = columnifexists("id_s", "None"), CallerIPAddress = columnifexists("CallerIPAddress", "None"), clientInfo_s = columnifexists("clientInfo_s", "None")
| where ResultType !~ "None" and isnotempty(ResultType)
| where identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g !~ "None" and isnotempty(identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g)
| where id_s !~ "None" and isnotempty(id_s)
| where CallerIPAddress !~ "None" and isnotempty(CallerIPAddress)
| where clientInfo_s !~ "None" and isnotempty(clientInfo_s)
| where requestUri_s !~ "None" and isnotempty(requestUri_s)
| where ResourceType =~ "VAULTS" and ResultType =~ "Success"
| where OperationName in (OperationList)
| summarize PerOperationCount=count(), LatestAnomalyTime = arg_max(TimeGenerated,*) by bin(TimeGenerated,1h), Resource, OperationName, id_s, CallerIPAddress, identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g, requestUri_s, clientInfo_s
) on Resource, TimeGenerated
| summarize EventCount=count(), OperationNameList = make_set(OperationName), RequestURLList = make_set(requestUri_s, 100), AccountList = make_set(identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g, 100), AccountMax = arg_max(identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g,*) by Resource, id_s, clientInfo_s, LatestAnomalyTime
| extend timestamp = LatestAnomalyTime, IPCustomEntity = CallerIPAddress, AccountCustomEntity = AccountMax
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
  tactics = ['CredentialAccess']
  techniques = ['T1003']
  display_name = Azure Key Vault access TimeSeries anomaly
  description = <<EOT
Indentifies a sudden increase in count of Azure Key Vault secret or vault access operations by CallerIPAddress. The query leverages a built-in KQL anomaly detection algorithm
to find large deviations from baseline Azure Key Vault access patterns. Any sudden increase in the count of Azure Key Vault accesses can be an
indication of adversary dumping credentials via automated methods. If you are seeing any noise, try filtering known source(IP/Account) and user-agent combinations.
TimeSeries Reference Blog: https://techcommunity.microsoft.com/t5/azure-sentinel/looking-for-unknown-anomalies-what-is-normal-time-series/ba-p/555052
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
