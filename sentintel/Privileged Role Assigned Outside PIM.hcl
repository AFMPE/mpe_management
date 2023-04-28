resource "my_alert_rule" "rule_356" {
  name = "Privileged Role Assigned Outside PIM"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
AuditLogs
| where Category =~ "RoleManagement"
| where OperationName has "Add member to role outside of PIM"
        or (LoggedByService == "Core Directory" and OperationName == "Add member to role" and Identity !has "MS-PIM")
| extend AccountCustomEntity = tostring(TargetResources[0].userPrincipalName), IPCustomEntity = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
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
  tactics = ['PrivilegeEscalation']
  techniques = ['T1078']
  display_name = Privileged Role Assigned Outside PIM
  description = <<EOT
Identifies a privileged role being assigned to a user outside of PIM
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#things-to-monitor-1
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
