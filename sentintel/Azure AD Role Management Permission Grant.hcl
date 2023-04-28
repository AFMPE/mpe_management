resource "my_alert_rule" "rule_145" {
  name = "Azure AD Role Management Permission Grant"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT2H
  query_period = PT2H
  severity = High
  query = <<EOF
AuditLogs
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where AADOperationType =~ "Assign"
| where ActivityDisplayName has_any ("Add delegated permission grant","Add app role assignment to service principal")
| mv-expand TargetResources
| mv-expand TargetResources.modifiedProperties
| extend displayName_ = tostring(TargetResources_modifiedProperties.displayName)
| where displayName_ has_any ("AppRole.Value","DelegatedPermissionGrant.Scope")
| extend Permission = tostring(parse_json(tostring(TargetResources_modifiedProperties.newValue)))
| where Permission has "RoleManagement.ReadWrite.Directory"
| extend InitiatingApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
| extend Initiator = iif(isnotempty(InitiatingApp), InitiatingApp, tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName))
| extend Target = tostring(parse_json(tostring(TargetResources.modifiedProperties[4].newValue)))
| extend TargetId = iif(displayName_ =~ 'DelegatedPermissionGrant.Scope',
  tostring(parse_json(tostring(TargetResources.modifiedProperties[2].newValue))),
  tostring(parse_json(tostring(TargetResources.modifiedProperties[3].newValue))))
| summarize by bin(TimeGenerated, 1h), OperationName, Initiator, Target, TargetId, Result
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = Initiator
    }
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = Target
    }
  }
  tactics = ['Persistence', 'Impact']
  techniques = ['T1078', 'T1098']
  display_name = Azure AD Role Management Permission Grant
  description = <<EOT
Identifies when the Microsoft Graph RoleManagement.ReadWrite.Directory (Delegated or Application) permission is granted to a service principal.
This permission allows an application to read and manage the role-based access control (RBAC) settings for your company's directory.
An adversary could use this permission to add an Azure AD object to an Admin directory role and escalate privileges.
Ref : https://docs.microsoft.com/graph/permissions-reference#role-management-permissions
Ref : https://docs.microsoft.com/graph/api/directoryrole-post-members?view=graph-rest-1.0&tabs=http
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
