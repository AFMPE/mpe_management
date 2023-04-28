resource "my_alert_rule" "rule_70" {
  name = "Multiple admin membership removals from newly created admin"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P7D
  severity = Medium
  query = <<EOF
let lookback = 7d; 
let timeframe = 1h; 
let GlobalAdminsRemoved = AuditLogs 
| where TimeGenerated > ago(timeframe) 
| where Category =~ "RoleManagement" 
| where AADOperationType in ("Unassign", "RemoveEligibleRole") 
| where ActivityDisplayName has_any ("Remove member from role", "Remove eligible member from role") 
| mv-expand TargetResources 
| mv-expand TargetResources.modifiedProperties 
| extend displayName_ = tostring(TargetResources_modifiedProperties.displayName) 
| where displayName_ =~ "Role.DisplayName" 
| extend RoleName = tostring(parse_json(tostring(TargetResources_modifiedProperties.oldValue))) 
| where RoleName == "Global Administrator" // Add other Privileged role if applicable 
| extend InitiatingApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName) 
| extend Initiator = iif(isnotempty(InitiatingApp), InitiatingApp, tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)) 
| where Initiator != "MS-PIM"  // Filtering PIM events 
| extend Target = tostring(TargetResources.userPrincipalName) 
| summarize RemovedGlobalAdminTime = max(TimeGenerated), TargetAdmins = make_set(Target) by OperationName,  RoleName, Initiator, Result; 
let GlobalAdminsAdded = AuditLogs 
| where TimeGenerated > ago(lookback) 
| where Category =~ "RoleManagement" 
| where AADOperationType in ("Assign", "AssignEligibleRole") 
| where ActivityDisplayName has_any ("Add eligible member to role", "Add member to role") and Result == "success" 
| mv-expand TargetResources 
| mv-expand TargetResources.modifiedProperties 
| extend displayName_ = tostring(TargetResources_modifiedProperties.displayName) 
| where displayName_ =~ "Role.DisplayName" 
| extend RoleName = tostring(parse_json(tostring(TargetResources_modifiedProperties.newValue))) 
| where RoleName == "Global Administrator" // Add other Privileged role if applicable 
| extend InitiatingApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName) 
| extend Initiator = iif(isnotempty(InitiatingApp), InitiatingApp, tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)) 
| where Initiator != "MS-PIM"  // Filtering PIM events 
| extend Target = tostring(TargetResources.userPrincipalName) 
| summarize AddedGlobalAdminTime = max(TimeGenerated) by OperationName,  RoleName, Target, Initiator, Result 
| extend AccountCustomEntity = Target; 
GlobalAdminsAdded 
| join kind= inner GlobalAdminsRemoved on $left.Target == $right.Initiator 
| where AddedGlobalAdminTime < RemovedGlobalAdminTime 
| extend NoofAdminsRemoved = array_length(TargetAdmins) 
| where NoofAdminsRemoved > 1
| project AddedGlobalAdminTime, Initiator, Target, AccountCustomEntity, RemovedGlobalAdminTime, TargetAdmins, NoofAdminsRemoved
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = ['T1531']
  display_name = Multiple admin membership removals from newly created admin
  description = <<EOT
This query detects when newly created Global admin removes multiple existing global admins which can be an attempt by adversaries to lock down organization and retain sole access. 
 Investigate reasoning and intention of multiple membership removal by new Global admins and take necessary actions accordingly.
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
