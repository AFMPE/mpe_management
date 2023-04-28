resource "my_alert_rule" "rule_208" {
  name = "Azure DevOps New Extension Added"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let allowed_publishers = dynamic([]);
AzureDevOpsAuditing
| where OperationName =~ "Extension.Installed"
| extend ExtensionName = tostring(Data.ExtensionName)
| extend PublisherName = tostring(Data.PublisherName)
| where PublisherName !in (allowed_publishers)
| project-reorder TimeGenerated, OperationName, ExtensionName, PublisherName, ActorUPN, IpAddress, UserAgent, ScopeDisplayName, Data
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
  tactics = ['Persistence']
  techniques = ['T1505']
  display_name = Azure DevOps New Extension Added
  description = <<EOT
Extensions add additional features to Azure DevOps. An attacker could use a malicious extension to conduct malicious activity. 
This query looks for new extensions that are not from a configurable list of approved publishers.
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
