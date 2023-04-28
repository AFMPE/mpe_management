resource "my_alert_rule" "rule_131" {
  name = "Suspicious granting of permissions to an account"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
let starttime = 14d;
let endtime = 1d;
// The number of operations below which an IP address is considered an unusual source of role assignment operations
let alertOperationThreshold = 5;
let createRoleAssignmentActivity = AzureActivity
| where OperationNameValue =~ "microsoft.authorization/roleassignments/write";
createRoleAssignmentActivity 
| where TimeGenerated between (ago(starttime) .. ago(endtime))
| summarize count() by CallerIpAddress, Caller
| where count_ >= alertOperationThreshold
| join kind = rightanti ( 
createRoleAssignmentActivity
| where TimeGenerated > ago(endtime)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ActivityTimeStamp = make_set(TimeGenerated), ActivityStatusValue = make_set(ActivityStatusValue), 
OperationIds = make_set(OperationId), CorrelationId = make_set(CorrelationId), ActivityCountByCallerIPAddress = count()  
by ResourceId, CallerIpAddress, Caller, OperationNameValue, Resource, ResourceGroup
) on CallerIpAddress, Caller
| extend timestamp = StartTimeUtc, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress
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
  tactics = ['Persistence', 'PrivilegeEscalation']
  techniques = ['T1078', 'T1098']
  display_name = Suspicious granting of permissions to an account
  description = <<EOT
Identifies IPs from which users grant access to other users on azure resources and alerts when a previously unseen source IP address is used.
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
