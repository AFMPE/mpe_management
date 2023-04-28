resource "my_alert_rule" "rule_200" {
  name = "Account created from non-approved sources"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P7D
  severity = Medium
  query = <<EOF
let core_domains = (SigninLogs
  | where TimeGenerated > ago(7d)
  | where ResultType == 0
  | extend domain = tolower(split(UserPrincipalName, "@")[1])
  | summarize by tostring(domain));
  let alternative_domains = (SigninLogs
  | where TimeGenerated > ago(7d)
  | where isnotempty(AlternateSignInName)
  | where ResultType == 0
  | extend domain = tolower(split(AlternateSignInName, "@")[1])
  | summarize by tostring(domain));
  AuditLogs
  | where TimeGenerated > ago(1d)
  | where OperationName =~ "Add User"
  | extend AddingUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend AddingSPN = tostring(parse_json(tostring(InitiatedBy.app)).servicePrincipalName)
  | extend AddedBy = iif(isnotempty(AddingUser), AddingUser, AddingSPN)
  | extend UserAdded = tostring(TargetResources[0].userPrincipalName)
  | extend Domain = tolower(split(UserAdded, "@")[1])
  | where Domain !in (core_domains) and Domain !in (alternative_domains)
  | project-away AddingUser
  | project-reorder TimeGenerated, UserAdded, Domain, AddedBy
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AddedBy
    }
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = UserAdded
    }
  }
  tactics = ['Persistence']
  techniques = ['T1136']
  display_name = Account created from non-approved sources
  description = <<EOT
This query looks for account being created from a domain that is not regularly seen in a tenant.
  Attackers may attempt to add accounts from these sources as a means of establishing persistant access to an environment.
  Created accounts should be investigated to ensure they were legitimated created.
  Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts#short-lived-accounts
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
