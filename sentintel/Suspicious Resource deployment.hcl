resource "my_alert_rule" "rule_249" {
  name = "Suspicious Resource deployment"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Low
  query = <<EOF
let szOperationNames = dynamic(["Microsoft.Compute/virtualMachines/write", "Microsoft.Resources/deployments/write"]);
let starttime = 14d;
let endtime = 1d;
let RareCaller = AzureActivity
| where TimeGenerated between (ago(starttime) .. ago(endtime))
| where OperationNameValue in~ (szOperationNames)
| project ResourceGroup, Caller, OperationNameValue, CallerIpAddress
| join kind=rightantisemi (
AzureActivity
| where TimeGenerated > ago(endtime)
| where OperationNameValue in~ (szOperationNames)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ActivityStatusValue = makeset(ActivityStatusValue), OperationIds = makeset(OperationId), CallerIpAddress = makeset(CallerIpAddress) 
by ResourceId, Caller, OperationNameValue, Resource, ResourceGroup
) on Caller, ResourceGroup 
| mvexpand CallerIpAddress
| where isnotempty(CallerIpAddress);
let Counts = RareCaller | summarize ActivityCountByCaller = count() by Caller;
RareCaller | join kind= inner (Counts) on Caller | project-away Caller1
| extend timestamp = StartTimeUtc, AccountCustomEntity = Caller, IPCustomEntity = tostring(CallerIpAddress)
| sort by ActivityCountByCaller desc nulls last
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
  display_name = Suspicious Resource deployment
  description = <<EOT
Identifies when a rare Resource and ResourceGroup deployment occurs by a previously unseen Caller.
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
