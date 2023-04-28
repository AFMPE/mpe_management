resource "my_alert_rule" "rule_21" {
  name = "Azure Active Directory Hybrid Health AD FS Service Delete"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
AzureActivity
| where CategoryValue == 'Administrative'
| where ResourceProviderValue =~ 'Microsoft.ADHybridHealthService'
| where _ResourceId contains 'AdFederationService'
| where OperationNameValue =~ 'Microsoft.ADHybridHealthService/services/delete'
| extend claimsJson = parse_json(Claims)
| extend AppId = tostring(claimsJson.appid)
| extend AccountName = tostring(claimsJson.name)
| project-away claimsJson
| extend timestamp = TimeGenerated, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress
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
  tactics = ['DefenseEvasion']
  techniques = ['T1578']
  display_name = Azure Active Directory Hybrid Health AD FS Service Delete
  description = <<EOT
This detection uses AzureActivity logs (Administrative category) to identify the deletion of an Azure AD Hybrid health AD FS service instance in a tenant.
A threat actor can create a new AD Health ADFS service and create a fake server to spoof AD FS signing logs.
The health AD FS service can then be deleted after it is not longer needed via HTTP requests to Azure.
More information in this blog https://o365blog.com/post/hybridhealthagent/
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
