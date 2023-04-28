resource "my_alert_rule" "rule_171" {
  name = "Account Created and Deleted in Short Timeframe"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P1D
  severity = High
  query = <<EOF
let queryfrequency = 1h;
let queryperiod = 1d;
AuditLogs
| where TimeGenerated > ago(queryfrequency)
| where OperationName =~ "Delete user"
//extend UserPrincipalName = tostring(TargetResources[0].userPrincipalName)
| extend UserPrincipalName = extract(@'([a-f0-9]{32})?(.*)', 2, tostring(TargetResources[0].userPrincipalName))
| extend DeletedByUser = tostring(InitiatedBy.user.userPrincipalName), DeletedByIPAddress = tostring(InitiatedBy.user.ipAddress)
| extend DeletedByApp = tostring(InitiatedBy.app.displayName)
| project Deletion_TimeGenerated = TimeGenerated, UserPrincipalName, DeletedByUser, DeletedByIPAddress, DeletedByApp, Deletion_AdditionalDetails = AdditionalDetails, Deletion_InitiatedBy = InitiatedBy, Deletion_TargetResources = TargetResources
| join kind=inner (
    AuditLogs
    | where TimeGenerated > ago(queryperiod)
    | where OperationName =~ "Add user"
    | extend UserPrincipalName = tostring(TargetResources[0].userPrincipalName)
    | project-rename Creation_TimeGenerated = TimeGenerated
) on UserPrincipalName
| extend TimeDelta = Deletion_TimeGenerated - Creation_TimeGenerated
| where  TimeDelta between (time(0s) .. queryperiod)
| extend CreatedByUser = tostring(InitiatedBy.user.userPrincipalName), CreatedByIPAddress = tostring(InitiatedBy.user.ipAddress)
| extend CreatedByApp = tostring(InitiatedBy.app.displayName)
| project Creation_TimeGenerated, Deletion_TimeGenerated, TimeDelta, UserPrincipalName, DeletedByUser, DeletedByIPAddress, DeletedByApp, CreatedByUser, CreatedByIPAddress, CreatedByApp, Creation_AdditionalDetails = AdditionalDetails, Creation_InitiatedBy = InitiatedBy, Creation_TargetResources = TargetResources, Deletion_AdditionalDetails, Deletion_InitiatedBy, Deletion_TargetResources
| extend timestamp = Deletion_TimeGenerated, CustomAccountEntity = UserPrincipalName, IPCustomEntity = DeletedByIPAddress
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = CustomAccountEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['InitialAccess']
  techniques = ['T1078']
  display_name = Account Created and Deleted in Short Timeframe
  description = <<EOT
Search for user principal name (UPN) events. Look for accounts created and then deleted in under 24 hours. Attackers may create an account for their use, and then remove the account when no longer needed.
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts#short-lived-account
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
