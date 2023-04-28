resource "my_alert_rule" "rule_254" {
  name = "Rare subscription-level operations in Azure"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Low
  query = <<EOF
let starttime = 14d;
let endtime = 1d;
// The number of operations below which an IP address is considered an unusual source of role assignment operations
let alertOperationThreshold = 5;
let SensitiveOperationList =  dynamic(["microsoft.compute/snapshots/write", "microsoft.network/networksecuritygroups/write", "microsoft.storage/storageaccounts/listkeys/action"]);
let SensitiveActivity = AzureActivity
| where OperationNameValue in~ (SensitiveOperationList) or OperationNameValue hassuffix "listkeys/action"
| where ActivityStatusValue =~ "Succeeded";
SensitiveActivity
| where TimeGenerated between (ago(starttime) .. ago(endtime))
| summarize count() by CallerIpAddress, Caller, OperationNameValue
| where count_ >= alertOperationThreshold
| join kind = rightanti ( 
SensitiveActivity
| where TimeGenerated >= ago(endtime)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ActivityTimeStamp = makelist(TimeGenerated), ActivityStatusValue = makelist(ActivityStatusValue), 
OperationIds = makelist(OperationId), CorrelationIds = makelist(CorrelationId), Resources = makelist(Resource), ResourceGroups = makelist(ResourceGroup), ResourceIds = makelist(ResourceId), ActivityCountByCallerIPAddress = count()  
by CallerIpAddress, Caller, OperationNameValue
) on CallerIpAddress, Caller, OperationNameValue
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
  tactics = ['CredentialAccess', 'Persistence']
  techniques = ['T1098', 'T1003']
  display_name = Rare subscription-level operations in Azure
  description = <<EOT
This query looks for a few sensitive subscription-level events based on Azure Activity Logs. 
 For example this monitors for the operation name 'Create or Update Snapshot' which is used for creating backups but could be misused by attackers 
 to dump hashes or extract sensitive information from the disk.
EOT
  enabled = False
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
