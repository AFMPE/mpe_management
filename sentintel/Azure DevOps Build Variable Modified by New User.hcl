resource "my_alert_rule" "rule_235" {
  name = "Azure DevOps Build Variable Modified by New User"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
let lookback = 14d;
let timeframe = 1d;
let historical_data =
AzureDevOpsAuditing
| where TimeGenerated > ago(lookback) and TimeGenerated < ago(timeframe)
| where OperationName =~ "Library.VariableGroupModified"
| extend variables = Data.Variables
| extend VariableGroupId = tostring(Data.VariableGroupId)
| extend UserKey = strcat(VariableGroupId, "-", ActorUserId)
| project UserKey;
AzureDevOpsAuditing
| where TimeGenerated > ago(timeframe)
| where OperationName =~ "Library.VariableGroupModified"
| extend VariableGroupName = tostring(Data.VariableGroupName)
| extend VariableGroupId = tostring(Data.VariableGroupId)
| extend UserKey = strcat(VariableGroupId, "-", ActorUserId)
| where UserKey !in (historical_data)
| project-away UserKey
| project-reorder TimeGenerated, VariableGroupName, ActorUPN, IpAddress, UserAgent
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress
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
  tactics = ['DefenseEvasion']
  techniques = ['T1578']
  display_name = Azure DevOps Build Variable Modified by New User
  description = <<EOT
Variables can be configured and used at any stage of the build process in Azure DevOps to inject values. An attacker with the required permissions could modify 
or add to these variables to conduct malicious activity such as changing paths or remote endpoints called during the build. As variables are often changed by users, 
just detecting these changes would have a high false positive rate. This detection looks for modifications to variable groups where that user has not been observed 
modifying them before.
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
