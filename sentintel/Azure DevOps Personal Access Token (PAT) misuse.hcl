resource "my_alert_rule" "rule_68" {
  name = "Azure DevOps Personal Access Token (PAT) misuse"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = High
  query = <<EOF
// Allowlisted UPNs should likely stay empty
let AllowlistedUpns = datatable(UPN:string)['foo@bar.com', 'test@foo.com'];
// Operation Name parts that will alert
let HasAnyBlocklist = datatable(OperationNamePart:string)['Security.','Project.','AuditLog.','Extension.'];
// Distinct Operation Names that will flag
let HasExactBlocklist = datatable(OperationName:string)['Group.UpdateGroupMembership.Add','Library.ServiceConnectionExecuted','Pipelines.PipelineModified',
'Release.ReleasePipelineModified', 'Git.RefUpdatePoliciesBypassed'];
AzureDevOpsAuditing
| where AuthenticationMechanism startswith "PAT" and (OperationName has_any (HasAnyBlocklist) or OperationName in (HasExactBlocklist))
  and ActorUPN !in (AllowlistedUpns)
| project TimeGenerated, AuthenticationMechanism, ProjectName, ActorUPN, ActorDisplayName, IpAddress, UserAgent, OperationName, Details, Data
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
  tactics = ['Execution', 'Impact']
  techniques = ['T1496', 'T1559']
  display_name = Azure DevOps Personal Access Token (PAT) misuse
  description = <<EOT
This Alert detects whenever a PAT is used in ways that PATs are not normally used. May require an allow list and baselining.
Reference - https://docs.microsoft.com/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=preview-page
Use this query for baselining:
AzureDevOpsAuditing
| distinct OperationName
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
