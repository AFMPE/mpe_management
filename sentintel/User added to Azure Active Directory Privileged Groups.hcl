resource "my_alert_rule" "rule_112" {
  name = "User added to Azure Active Directory Privileged Groups"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
let OperationList = dynamic(["Add member to role","Add member to role in PIM requested (permanent)"]);
let PrivilegedGroups = dynamic(["UserAccountAdmins","PrivilegedRoleAdmins","TenantAdmins"]);
AuditLogs
//| where LoggedByService =~ "Core Directory"
| where Category =~ "RoleManagement"
| where OperationName in~ (OperationList)
| mv-expand TargetResources
| extend modProps = parse_json(TargetResources).modifiedProperties
| mv-expand bagexpansion=array modProps
| evaluate bag_unpack(modProps)
| extend displayName = column_ifexists("displayName", "NotAvailable"), newValue = column_ifexists("newValue", "NotAvailable")
| where displayName =~ "Role.WellKnownObjectName"
| extend DisplayName = displayName, GroupName = replace('"','',newValue)
| extend initByApp = parse_json(InitiatedBy).app, initByUser = parse_json(InitiatedBy).user
| extend AppId = initByApp.appId, 
InitiatedByDisplayName = case(isnotempty(initByApp.displayName), initByApp.displayName, isnotempty(initByUser.displayName), initByUser.displayName, "not available"),
ServicePrincipalId = tostring(initByApp.servicePrincipalId),
ServicePrincipalName = tostring(initByApp.servicePrincipalName),
UserId = initByUser.id,
UserIPAddress = initByUser.ipAddress,
UserRoles = initByUser.roles,
UserPrincipalName = tostring(initByUser.userPrincipalName),
TargetUserPrincipalName = tostring(TargetResources.userPrincipalName)
| where GroupName in~ (PrivilegedGroups)
// If you don't want to alert for operations from PIM, remove below filtering for MS-PIM.
| where InitiatedByDisplayName != "MS-PIM"
| project TimeGenerated, AADOperationType, Category, OperationName, AADTenantId, AppId, InitiatedByDisplayName, ServicePrincipalId, ServicePrincipalName, DisplayName, GroupName, UserId, UserIPAddress, UserRoles, UserPrincipalName, TargetUserPrincipalName
| extend timestamp = TimeGenerated, AccountCustomEntity = case(isnotempty(ServicePrincipalName), ServicePrincipalName, isnotempty(ServicePrincipalId), ServicePrincipalId, isnotempty(UserPrincipalName), UserPrincipalName, "not available")
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
      column_name = TargetUserPrincipalName
    }
  }
  tactics = ['Persistence', 'PrivilegeEscalation']
  techniques = ['T1078', 'T1098']
  display_name = User added to Azure Active Directory Privileged Groups
  description = <<EOT
This will alert when a user is added to any of the Privileged Groups.
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.
For Administrator role permissions in Azure Active Directory please see https://docs.microsoft.com/azure/active-directory/users-groups-roles/directory-assign-admin-roles
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
