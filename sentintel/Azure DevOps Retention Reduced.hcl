resource "my_alert_rule" "rule_274" {
  name = "Azure DevOps Retention Reduced"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
AzureDevOpsAuditing
| where OperationName =~ "Pipelines.PipelineRetentionSettingChanged"
| where Data.SettingName in ("PurgeArtifacts", "PurgeRuns")
| where Data.NewValue == 1 or Data.NewValue < Data.OldValue/2
| project-reorder TimeGenerated, OperationName, ActorUPN, IpAddress, UserAgent, Data
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
  techniques = ['T1564']
  display_name = Azure DevOps Retention Reduced
  description = <<EOT
AzureDevOps retains items such as run records and produced artifacts for a configurable amount of time. An attacker looking to reduce the footprint left by their malicious activity may look to reduce the retention time for artifacts and runs.
This query will look for where retention has been reduced to the minimum level - 1, or reduced by more than half.
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
