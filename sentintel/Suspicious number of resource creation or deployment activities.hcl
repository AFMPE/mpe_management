resource "my_alert_rule" "rule_59" {
  name = "Suspicious number of resource creation or deployment activities"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P7D
  severity = Medium
  query = <<EOF
let szOperationNames = dynamic(["microsoft.compute/virtualMachines/write", "microsoft.resources/deployments/write"]);
let starttime = 7d;
let endtime = 1d;
AzureActivity
| where TimeGenerated between (startofday(ago(starttime)) .. startofday(ago(endtime)))
| where OperationNameValue  in~ (szOperationNames)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ActivityTimeStamp = makelist(TimeGenerated), ActivityStatusValue = makelist(ActivityStatusValue), 
OperationIds = makelist(OperationId), CallerIpAddress = makelist(CallerIpAddress), CorrelationId = makelist(CorrelationId) 
by ResourceId, Caller, OperationNameValue, Resource, ResourceGroup
| mvexpand CallerIpAddress
| where isnotempty(CallerIpAddress)
| make-series dResourceCount=dcount(ResourceId)  default=0 on StartTimeUtc in range(startofday(ago(7d)), now(), 1d) 
by Caller, tostring(ActivityTimeStamp), tostring(ActivityStatusValue), tostring(OperationIds), tostring(CallerIpAddress), tostring(CorrelationId), ResourceId, OperationNameValue , Resource, ResourceGroup
| extend (RSquare,Slope,Variance,RVariance,Interception,LineFit)=series_fit_line(dResourceCount)
| where Slope > 0.2
| join kind=leftsemi (
// Last day's activity is anomalous
AzureActivity
| where TimeGenerated >= startofday(ago(endtime))
| where OperationNameValue in~ (szOperationNames)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ActivityTimeStamp = makelist(TimeGenerated), ActivityStatusValue = makelist(ActivityStatusValue), 
OperationIds = makelist(OperationId), CallerIpAddress = makelist(CallerIpAddress), CorrelationId = makelist(CorrelationId) 
by ResourceId, Caller, OperationNameValue, Resource, ResourceGroup
| mvexpand CallerIpAddress
| where isnotempty(CallerIpAddress)
| make-series dResourceCount=dcount(ResourceId)  default=0 on StartTimeUtc in range(startofday(ago(1d)), now(), 1d) 
by Caller, tostring(ActivityTimeStamp), tostring(ActivityStatusValue), tostring(OperationIds), tostring(CallerIpAddress), tostring(CorrelationId), ResourceId, OperationNameValue , Resource, ResourceGroup
| extend (RSquare,Slope,Variance,RVariance,Interception,LineFit)=series_fit_line(dResourceCount)
| where Slope > 0.2    
) on Caller, CallerIpAddress        
| mvexpand todynamic(ActivityTimeStamp), todynamic(ActivityStatusValue), todynamic(OperationIds), todynamic(CorrelationId)
| extend timestamp = ActivityTimeStamp, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress
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
  tactics = ['Impact']
  techniques = ['T1496']
  display_name = Suspicious number of resource creation or deployment activities
  description = <<EOT
Indicates when an anomalous number of VM creations or deployment activities occur in Azure via the AzureActivity log.
The anomaly detection identifies activities that have occurred both since the start of the day 1 day ago and the start of the day 7 days ago.
The start of the day is considered 12am UTC time.
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
