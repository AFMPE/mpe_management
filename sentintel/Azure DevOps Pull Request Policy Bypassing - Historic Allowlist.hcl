resource "my_alert_rule" "rule_238" {
  name = "Azure DevOps Pull Request Policy Bypassing - Historic Allowlist"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT3H
  query_period = P14D
  severity = Medium
  query = <<EOF
let starttime = 14d;
let endtime = 3h;
// Add full UPN (user@domain.com) to Authorized Bypassers to ignore policy bypasses by certain authorized users
let AuthorizedBypassers = dynamic(['foo@baz.com', 'test@foo.com']);
let historicBypassers = AzureDevOpsAuditing
| where TimeGenerated between (ago(starttime) .. ago(endtime))
| where OperationName == 'Git.RefUpdatePoliciesBypassed'
| distinct ActorUPN;
AzureDevOpsAuditing
| where TimeGenerated >= ago(endtime)
| where OperationName == 'Git.RefUpdatePoliciesBypassed'
| where ActorUPN !in (historicBypassers) and ActorUPN !in (AuthorizedBypassers)
| parse ScopeDisplayName with OrganizationName '(Organization)'
| project TimeGenerated, ActorUPN, IpAddress, UserAgent, OrganizationName, ProjectName, RepoName = Data.RepoName, AlertDetails = Details, Branch = Data.Name, 
  BypassReason = Data.BypassReason, PRLink = strcat('https://dev.azure.com/', OrganizationName, '/', ProjectName, '/_git/', Data.RepoName, '/pullrequest/', Data.PullRequestId)
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
  techniques = ['T1098']
  display_name = Azure DevOps Pull Request Policy Bypassing - Historic Allowlist
  description = <<EOT
This detection builds a Allowlist of historic PR policy bypasses and compares to recent history, flagging a non manually allowlisted, non historic pull request bypass.
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
