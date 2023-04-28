resource "my_alert_rule" "rule_83" {
  name = "Azure VM Run Command operation executed during suspicious login window"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P2D
  severity = High
  query = <<EOF
AzureActivity
// Isolate run command actions
| where OperationNameValue == "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION"
// Confirm that the operation impacted a virtual machine
| where Authorization has "virtualMachines"
// Each runcommand operation consists of three events when successful, Started, Accepted (or Rejected), Successful (or Failed).
| summarize StartTime=min(TimeGenerated), EndTime=max(TimeGenerated), max(CallerIpAddress), make_list(ActivityStatusValue) by CorrelationId, Authorization, Caller
// Limit to Run Command executions that Succeeded
| where list_ActivityStatusValue has "Success"
// Extract data from the Authorization field
| extend Authorization_d = parse_json(Authorization)
| extend Scope = Authorization_d.scope
| extend Scope_s = split(Scope, "/")
| extend Subscription = tostring(Scope_s[2])
| extend VirtualMachineName = tostring(Scope_s[-1])
| project StartTime, EndTime, Subscription, VirtualMachineName, CorrelationId, Caller, CallerIpAddress=max_CallerIpAddress
// Create a join key using  the Caller (UPN)
| extend joinkey = tolower(Caller)
// Join the Run Command actions to UEBA data
| join kind = inner (
    BehaviorAnalytics
    // We are specifically interested in unusual logins
    | where EventSource == "Azure AD" and ActivityInsights.ActionUncommonlyPerformedByUser == "True"
    | project UEBAEventTime=TimeGenerated, UEBAActionType=ActionType, UserPrincipalName, UEBASourceIPLocation=SourceIPLocation, UEBAActivityInsights=ActivityInsights, UEBAUsersInsights=UsersInsights
    | where isnotempty(UserPrincipalName) and isnotempty(UEBASourceIPLocation)
    | extend joinkey = tolower(UserPrincipalName)
) on joinkey
// Create a window around the UEBA event times, check to see if the Run Command action was performed within them
| extend UEBAWindowStart = UEBAEventTime - 1h, UEBAWindowEnd = UEBAEventTime + 6h
| where StartTime between (UEBAWindowStart .. UEBAWindowEnd)
| project StartTime, EndTime, Subscription, VirtualMachineName, Caller, CallerIpAddress, UEBAEventTime, UEBAActionType, UEBASourceIPLocation, UEBAActivityInsights, UEBAUsersInsights
| extend timestamp = StartTime, AccountCustomEntity=Caller, IPCustomEntity=CallerIpAddress
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
  tactics = ['LateralMovement', 'CredentialAccess']
  techniques = ['T1570', 'T1212']
  display_name = Azure VM Run Command operation executed during suspicious login window
  description = <<EOT
Identifies when the Azure Run Command operation is executed by a UserPrincipalName and IP Address  
that has resulted in a recent user entity behaviour alert.
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
