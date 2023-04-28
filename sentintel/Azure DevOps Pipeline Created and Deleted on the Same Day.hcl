resource "my_alert_rule" "rule_288" {
  name = "Azure DevOps Pipeline Created and Deleted on the Same Day"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P3D
  query_period = P3D
  severity = Medium
  query = <<EOF
let timeframe = 3d;
// Get Release Pipeline Creation Events and group by day
AzureDevOpsAuditing
| where TimeGenerated > ago(timeframe)
| where OperationName =~ "Release.ReleasePipelineCreated"
// Group by day
| extend timekey = bin(TimeGenerated, 1d)
| extend PipelineId = tostring(Data.PipelineId)
| extend PipelineName = tostring(Data.PipelineName)
// Rename some columns to make output clearer
| project-rename TimeCreated = TimeGenerated, CreatingUser = ActorUPN, CreatingUserAgent = UserAgent, CreatingIP = IpAddress
// Join with Release Pipeline Deletions where Pipeline ID is the same and deletion occurred on same day as creation
| join (AzureDevOpsAuditing
| where TimeGenerated > ago(timeframe)
| where OperationName =~ "Release.ReleasePipelineDeleted"
// Group by day
| extend timekey = bin(TimeGenerated, 1d)
| extend PipelineId = tostring(Data.PipelineId)
| extend PipelineName = tostring(Data.PipelineName)
// Rename some things to make the output clearer
| project-rename TimeDeleted = TimeGenerated, DeletingUser = ActorUPN, DeletingUserAgent = UserAgent, DeletingIP = IpAddress) on PipelineId, timekey
| project TimeCreated, TimeDeleted, PipelineName, PipelineId, CreatingUser, CreatingIP, CreatingUserAgent, DeletingUser, DeletingIP, DeletingUserAgent, ScopeDisplayName, ProjectName, Data, OperationName, OperationName1
| extend timestamp = TimeCreated, AccountCustomEntity = CreatingUser, IPCustomEntity = CreatingIP
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = DeletingUser
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = DeletingIP
    }
  }
  tactics = ['Execution']
  techniques = ['T1072']
  display_name = Azure DevOps Pipeline Created and Deleted on the Same Day
  description = <<EOT
An attacker with access to Azure DevOps could create a pipeline to inject artifacts used by other pipelines, 
or to create a malicious software build that looks legitimate by using a pipeline that incorporates legitimate elements. 
An attacker would also likely want to cover their tracks once conducting such activity. This query looks for Pipelines 
created and deleted within the same day, this is unlikely to be legitimate user activity in the majority of cases.
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
