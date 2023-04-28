resource "my_alert_rule" "rule_290" {
  name = "New Agent Added to Pool by New User or Added to a New OS Type"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
let lookback = 14d;
let timeframe = 1d;
// exclude allowed users from query such as the ADO service
let allowed_users = dynamic(["Azure DevOps Service"]);
union
// Look for agents being added to a pool of a OS type not seen with that pool before
(AzureDevOpsAuditing
| where TimeGenerated > ago(lookback) and TimeGenerated < ago(timeframe)
| where OperationName =~ "Library.AgentAdded"
| where ActorUPN !in (allowed_users)
| extend AgentPoolName = tostring(Data.AgentPoolName)
| extend OsDescription = tostring(Data.OsDescription)
| where isnotempty(OsDescription)
| extend OsDescription = tostring(split(OsDescription, "#", 0)[0])
| project AgentPoolName, OsDescription
| join kind=rightanti (AzureDevOpsAuditing
| where TimeGenerated > ago(timeframe)
| where OperationName == "Library.AgentAdded"
| extend AgentPoolName = tostring(Data.AgentPoolName)
| extend OsDescription = tostring(Data.OsDescription)
| where isnotempty(OsDescription)
| extend OsDescription = tostring(split(OsDescription, "#", 0)[0])) on AgentPoolName, OsDescription),
// Look for users addeing agents to a pool that they have not added agents to before.
(AzureDevOpsAuditing
| where TimeGenerated > ago(lookback) and TimeGenerated < ago(timeframe)
| extend AgentPoolName = tostring(Data.AgentPoolName)
| where ActorUPN !in (allowed_users)
| project AgentPoolName, ActorUPN
| join kind=rightanti (AzureDevOpsAuditing
| where TimeGenerated > ago(timeframe)
| where OperationName == "Library.AgentAdded"
| where ActorUPN !in (allowed_users)
| extend AgentPoolName = tostring(Data.AgentPoolName)
) on AgentPoolName, ActorUPN)
| extend AgentName = tostring(Data.AgentName)
| extend OsDescription = tostring(Data.OsDescription)
| extend SystemDetails = Data.SystemCapabilities
| project-reorder TimeGenerated, OperationName, ScopeDisplayName, AgentPoolName, AgentName, ActorUPN, IpAddress, UserAgent, OsDescription, SystemDetails, Data
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
  tactics = ['Execution']
  techniques = ['T1053']
  display_name = New Agent Added to Pool by New User or Added to a New OS Type
  description = <<EOT
As seen in attacks such as SolarWinds attackers can look to subvert a build process by controlling build servers. Azure DevOps uses agent pools to execute pipeline tasks. An attacker could insert compromised agents that they control into the pools in order to execute malicious code. This query looks for users adding agents to pools they have not added agents to before, or adding agents to a pool of an OS that has not been added to that pool before. This detection has potential for false positives so has a configurable allow list to allow for certain users to be excluded from the logic.
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
