resource "my_alert_rule" "rule_113" {
  name = "Azure Active Directory Hybrid Health AD FS Suspicious Application"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
// Azure AD Connect Health Agent - cf6d7e68-f018-4e0a-a7b3-126e053fb88d
// Azure Active Directory Connect - cb1056e2-e479-49de-ae31-7812af012ed8
let appList = dynamic(['cf6d7e68-f018-4e0a-a7b3-126e053fb88d','cb1056e2-e479-49de-ae31-7812af012ed8']);
let operationNamesList = dynamic(['Microsoft.ADHybridHealthService/services/servicemembers/action','Microsoft.ADHybridHealthService/services/delete']);
AzureActivity
| where CategoryValue == 'Administrative'
| where ResourceProviderValue =~ 'Microsoft.ADHybridHealthService'
| where _ResourceId contains 'AdFederationService'
| where OperationNameValue in~ (operationNamesList)
| extend claimsJson = parse_json(Claims)
| extend AppId = tostring(claimsJson.appid)
| extend AccountName = tostring(claimsJson.name)
| where AppId !in (appList)
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
  tactics = ['CredentialAccess', 'DefenseEvasion']
  techniques = ['T1528', 'T1550']
  display_name = Azure Active Directory Hybrid Health AD FS Suspicious Application
  description = <<EOT
This detection uses AzureActivity logs (Administrative category) to a suspicious application adding a server instance to an Azure AD Hybrid health AD FS service or deleting the AD FS service instance.
Usually the Azure AD Connect Health Agent application with ID cf6d7e68-f018-4e0a-a7b3-126e053fb88d is used to perform those operations.
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
