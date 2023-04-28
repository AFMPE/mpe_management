resource "my_alert_rule" "rule_373" {
  name = "New CloudShell User"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let match_window = 3m;
AzureActivity
| where ResourceGroup has "cloud-shell"
| where (OperationNameValue =~ "Microsoft.Storage/storageAccounts/listKeys/action") 
| where ActivityStatusValue == "Success"
| extend TimeKey = bin(TimeGenerated, match_window), AzureIP = CallerIpAddress
| join kind = inner
(AzureActivity
| where ResourceGroup has "cloud-shell"
| where (OperationNameValue =~ "Microsoft.Storage/storageAccounts/write") 
| extend TimeKey = bin(TimeGenerated, match_window), UserIP = CallerIpAddress
) on Caller, TimeKey
| summarize count() by TimeKey, Caller, ResourceGroup, SubscriptionId, TenantId, AzureIP, UserIP, HTTPRequest, Type, Properties, CategoryValue, OperationList = strcat(OperationNameValue, ' , ', OperationNameValue1)
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = Caller
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = UserIP
    }
  }
  tactics = ['Execution']
  techniques = ['T1059']
  display_name = New CloudShell User
  description = <<EOT
Identifies when a user creates an Azure CloudShell for the first time.
Monitor this activity to ensure only expected user are using CloudShell
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
