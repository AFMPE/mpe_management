resource "my_alert_rule" "rule_353" {
  name = "Azure DevOps Agent Pool Created Then Deleted"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P7D
  query_period = P14D
  severity = High
  query = <<EOF
let lookback = 14d;
let timewindow = 7d;
AzureDevOpsAuditing
| where TimeGenerated > ago(lookback)
| where OperationName =~ "Library.AgentPoolCreated"
| extend AgentCloudId = tostring(Data.AgentCloudId)
| extend PoolType = iif(isnotempty(AgentCloudId), "Azure VMs", "Self Hosted")
// Comment this line out to include cloud pools as well
| where PoolType == "Self Hosted"
| extend AgentPoolName = tostring(Data.AgentPoolName)
| extend AgentPoolId = tostring(Data.AgentPoolId)
| extend IsHosted = tostring(Data.IsHosted)
| extend IsLegacy = tostring(Data.IsLegacy)
| extend timekey = bin(TimeGenerated, timewindow)
// Join only with pools deleted in the same window
| join (AzureDevOpsAuditing
| where TimeGenerated > ago(lookback)
| where OperationName =~ "Library.AgentPoolDeleted"
| extend AgentPoolName = tostring(Data.AgentPoolName)
| extend AgentPoolId = tostring(Data.AgentPoolId)
| extend timekey = bin(TimeGenerated, timewindow)) on AgentPoolId, timekey
| project-reorder TimeGenerated, ActorUPN, UserAgent, IpAddress, AuthenticationMechanism, OperationName, AgentPoolName, IsHosted, IsLegacy, Data
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
  display_name = Azure DevOps Agent Pool Created Then Deleted
  description = <<EOT
As well as adding build agents to an existing pool to execute malicious activity within a pipeline, an attacker could create a complete new agent pool and use this for execution.
Azure DevOps allows for the creation of agent pools with Azure hosted infrastructure or self-hosted infrastructure. Given the additional customizability of self-hosted agents this 
detection focuses on the creation of new self-hosted pools. To further reduce false positive rates the detection looks for pools created and deleted relatively quickly (within 7 days by default), 
as an attacker is likely to remove a malicious pool once used in order to reduce/remove evidence of their activity.
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
