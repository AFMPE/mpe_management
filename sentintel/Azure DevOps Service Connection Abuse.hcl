resource "my_alert_rule" "rule_295" {
  name = "Azure DevOps Service Connection Abuse"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
// How many greater than Service Connections you want to view per build/release
let ServiceConnectionThreshold = 4;
let BypassDefIds = datatable(DefId:string, Type:string, ProjectName:string)
[
//"103", "Release", "ProjectA",
//"42", "Release", "ProjectB",
//"122", "Build", "ProjectB"
];
AzureDevOpsAuditing
| where OperationName == "Library.ServiceConnectionExecuted" 
| extend DefId = tostring(Data.DefinitionId), Type = tostring(Data.PlanType), ConnectionId = tostring(Data.ConnectionId)
| parse ScopeDisplayName with OrganizationName ' (Organization)'
| summarize CurrentCount = dcount(tostring(ConnectionId)), ConnectionNames = make_set(tostring(Data.ConnectionName)), StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) 
  by OrganizationName, tostring(DefId), tostring(Type), ProjectId, ProjectName
| where CurrentCount > ServiceConnectionThreshold
| join kind=anti BypassDefIds on $left.DefId==$right.DefId and $left.Type == $right.Type and $left.ProjectName == $right.ProjectName
| extend link = iif(
  Type == "Build", strcat('https://dev.azure.com/', OrganizationName, '/', ProjectName, '/_build?definitionId=', DefId),
  strcat('https://dev.azure.com/', OrganizationName, '/', ProjectName, '/_release?_a=releases&view=mine&definitionId=', DefId))
| extend timestamp = StartTime
EOF
  entity_mapping {
  }
  tactics = ['Persistence', 'Impact']
  techniques = ['T1098', 'T1496']
  display_name = Azure DevOps Service Connection Abuse
  description = <<EOT
Flags builds/releases that use a large number of service connections if they aren't manually in the allow list.
This is to determine if someone is hijacking a build/release and adding many service connections in order to abuse 
or dump credentials from service connections.
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
