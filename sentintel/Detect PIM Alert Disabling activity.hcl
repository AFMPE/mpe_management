resource "my_alert_rule" "rule_236" {
  name = "Detect PIM Alert Disabling activity"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
AuditLogs
| where LoggedByService =~ "PIM"
| where Category =~ "RoleManagement"
| where ActivityDisplayName has "Disable PIM Alert"
| extend IpAddress = case(
  isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), 
  isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),
  'Not Available')
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
  tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName)), UserRoles = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| project InitiatedBy, ActivityDateTime, ActivityDisplayName, IpAddress, AADOperationType, AADTenantId, ResourceId, CorrelationId, Identity
| extend timestamp = ActivityDateTime, IPCustomEntity = IpAddress, AccountCustomEntity = tolower(InitiatedBy), ResourceCustomEntity = ResourceId
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
    entity_type = AzureResource
    field_mappings {
      identifier = ResourceId
      column_name = ResourceCustomEntity
    }
  }
  tactics = ['Persistence', 'PrivilegeEscalation']
  techniques = ['T1078', 'T1098']
  display_name = Detect PIM Alert Disabling activity
  description = <<EOT
Privileged Identity Management (PIM) generates alerts when there is suspicious or unsafe activity in Azure Active Directory (Azure AD) organization. 
This query will help detect attackers attempts to disable in product PIM alerts which are associated with Azure MFA requirements and could indicate activation of privileged access
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
