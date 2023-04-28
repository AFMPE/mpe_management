resource "my_alert_rule" "rule_372" {
  name = "Guest accounts changed user type from guest to members in AzureAD"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
AuditLogs 
| where OperationName contains "Update user"
| where TargetResources[0].modifiedProperties[0].oldValue contains "Guest"
| extend InvitedUser = TargetResources[0].userPrincipalName
// Uncomment the below line if you want to get alerts for changed usertype from specific domains or users
//| where InvitedUser has_any ("CUSTOM DOMAIN NAME#", "#EXT#")
| extend InitiatedByActionUserInformation = iff(isnotempty(InitiatedBy.user.userPrincipalName), InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName)
| extend InitiatedByIPAdress = InitiatedBy.user.ipAddress 
| extend OldUserType = TargetResources[0].modifiedProperties[0].oldValue contains "Guest"
| extend NewUserType = TargetResources[0].modifiedProperties[0].newValue contains "Member"
| mv-expand OldUserType = TargetResources[0].modifiedProperties[0].oldValue to typeof(string)
| mv-expand NewUserType = TargetResources[0].modifiedProperties[0].newValue to typeof(string)
| where OldUserType != NewUserType
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = InvitedUser
    }
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = InitiatedByActionUserInformation
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = InitiatedByIPAdress
    }
  }
  tactics = ['InitialAccess', 'Persistence', 'Discovery']
  techniques = ['T1098']
  display_name = Guest accounts changed user type from guest to members in AzureAD
  description = <<EOT
Guest Accounts are added in the Organization Tenants to perform various tasks i.e projects execution, support etc.. This detection notifies when guest users are changed from user type as should be in AzureAD to member and gain other rights in the tenant.
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
