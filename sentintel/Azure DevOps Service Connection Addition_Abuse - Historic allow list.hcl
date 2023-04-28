resource "my_alert_rule" "rule_147" {
  name = "Azure DevOps Service Connection Addition_Abuse - Historic allow list"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT6H
  query_period = P14D
  severity = Medium
  query = <<EOF
let starttime = 14d;
let endtime = 6h;
// Ignore Build/Releases with less/equal this number
let ServiceConnectionThreshold = 3;
// New Connections need to exhibit execution of more "new" connections than this number.
let NewConnectionThreshold = 1;
// List of Builds/Releases to ignore in your space
let BypassDefIds = datatable(DefId:string, Type:string, ProjectName:string)
[
//"103", "Release", "ProjectA",
//"42", "Release", "ProjectB",
//"122", "Build", "ProjectB"
];
let HistoricDefs = AzureDevOpsAuditing
| where TimeGenerated between (ago(starttime) .. ago(endtime))
| where OperationName == "Library.ServiceConnectionExecuted" 
| extend DefId = tostring(Data.DefinitionId), Type = tostring(Data.PlanType), ConnectionId = tostring(Data.ConnectionId)
| summarize HistoricCount = dcount(tostring(ConnectionId)), ConnectionNames = make_set(tostring(Data.ConnectionName)) 
  by DefId = tostring(DefId), Type = tostring(Type), ProjectId, ProjectName, ActorUPN;
AzureDevOpsAuditing
| where TimeGenerated >= ago(endtime)
| where OperationName == "Library.ServiceConnectionExecuted" 
| extend DefId = tostring(Data.DefinitionId), Type = tostring(Data.PlanType), ConnectionId = tostring(Data.ConnectionId)
| parse ScopeDisplayName with OrganizationName ' (Organization)'
| summarize CurrentCount = dcount(tostring(ConnectionId)), ConnectionNames = make_set(tostring(Data.ConnectionName)), StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) 
  by OrganizationName, DefId = tostring(DefId), Type = tostring(Type), ProjectId, ProjectName, ActorUPN
| where CurrentCount > ServiceConnectionThreshold
| join (HistoricDefs) on ProjectId, DefId, Type, ActorUPN
| join kind=anti BypassDefIds on $left.DefId==$right.DefId and $left.Type == $right.Type and $left.ProjectName == $right.ProjectName
| extend link = iff(
Type == "Build", strcat('https://dev.azure.com/', OrganizationName, '/', ProjectName, '/_build?definitionId=', DefId),
strcat('https://dev.azure.com/', OrganizationName, '/', ProjectName, '/_release?_a=releases&view=mine&definitionId=', DefId))
| where CurrentCount >= HistoricCount + NewConnectionThreshold
| project StartTime, OrganizationName, ProjectName, DefId, link, RecentDistinctServiceConnections = CurrentCount, HistoricDistinctServiceConnections = HistoricCount, 
  RecentConnections = ConnectionNames, HistoricConnections = ConnectionNames1, ActorUPN
| extend timestamp = StartTime, AccountCustomEntity = ActorUPN
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
  }
  tactics = ['Persistence', 'Impact']
  techniques = ['T1098', 'T1496']
  display_name = Azure DevOps Service Connection Addition/Abuse - Historic allow list
  description = <<EOT
This detection builds an allow list of historic service connection use by Builds and Releases and compares to recent history, flagging growth of service connection use which are not manually included in the allow list and 
not historically included in the allow list Build/Release runs.  This is to determine if someone is hijacking a build/release and adding many service connections in order to abuse or dump credentials from service connections.
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
