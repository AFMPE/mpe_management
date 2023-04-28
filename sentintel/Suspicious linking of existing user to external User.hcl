resource "my_alert_rule" "rule_262" {
  name = "Suspicious linking of existing user to external User"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let lookback = 1d;
AuditLogs 
| where TimeGenerated > ago(lookback)
| where OperationName=~ "Update user" 
| where Result =~ "success" 
| mv-expand TargetResources 
| mv-expand TargetResources.modifiedProperties 
| extend displayName_ = tostring(TargetResources_modifiedProperties.displayName) , oldValue_ = tostring(TargetResources_modifiedProperties.oldValue), newValue_ = tostring(TargetResources_modifiedProperties.newValue)
| where displayName_ == "UserPrincipalName" and oldValue_ !has "#EXT" and newValue_ has "#EXT"
| extend InitiatingApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName) 
| extend Initiator = iif(isnotempty(InitiatingApp), InitiatingApp, tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)) , IPAddress = tostring(InitiatedBy.["user"].["ipAddress"])
| project TimeGenerated, AADTenantId, IPAddress, Initiator, displayName_, oldValue_, newValue_
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
      column_name = displayName_
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPAddress
    }
  }
  tactics = ['PrivilegeEscalation']
  techniques = ['T1078']
  display_name = Suspicious linking of existing user to external User
  description = <<EOT
 This query will detect when an attempt is made to update an existing user and link it to an guest or external identity. These activities are unusual and such linking of external 
identities should be investigated. In some cases you may see internal AAD sync accounts (Sync_) do this which may be benign
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
