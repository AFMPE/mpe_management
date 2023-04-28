resource "my_alert_rule" "rule_375" {
  name = "New PA, PCA, or PCAS added to Azure DevOps"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
AzureDevOpsAuditing
| where OperationName =~ "Group.UpdateGroupMembership.Add"
| where Details has_any ("Project Administrators", "Project Collection Administrators", "Project Collection Service Accounts", "Build Administrator")
| project-reorder TimeGenerated, Details, ActorUPN, IpAddress, UserAgent, AuthenticationMechanism, ScopeDisplayName
| extend timekey = bin(TimeGenerated, 1h)
| extend ActorUserId = tostring(Data.MemberId)
| project timekey, ActorUserId, AddingUser=ActorUPN, TimeAdded=TimeGenerated, PermissionGrantDetails = Details
// Get details of operations conducted by user soon after elevation of permissions
| join (AzureDevOpsAuditing
| extend ActorUserId = tostring(Data.MemberId)
| extend timekey = bin(TimeGenerated, 1h)) on timekey, ActorUserId
| summarize ActionsWhenAdded = make_set(OperationName) by ActorUPN, AddingUser, TimeAdded, PermissionGrantDetails, IpAddress, UserAgent
| extend timestamp = TimeAdded, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress
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
      column_name = AddingUser
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['InitialAccess']
  techniques = ['T1078']
  display_name = New PA, PCA, or PCAS added to Azure DevOps
  description = <<EOT
In order for an attacker to be able to conduct many potential attacks against Azure DevOps they will need to gain elevated permissions. This detection looks for users being granted key administrative permissions. If the principal of least privilege is applied the number of users granted these permissions should be small. Note that permissions can also be granted via Azure AD groups and monitoring of these should also be conducted.
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
