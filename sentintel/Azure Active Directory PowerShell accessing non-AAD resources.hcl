resource "my_alert_rule" "rule_100" {
  name = "Azure Active Directory PowerShell accessing non-AAD resources"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Low
  query = <<EOF
let aadFunc = (tableName:string){
table(tableName)
| where AppId =~ "1b730954-1685-4b74-9bfd-dac224a7b894" // AppDisplayName IS Azure Active Directory PowerShell
| where TokenIssuerType =~ "AzureAD"
| where ResourceIdentity !in ("00000002-0000-0000-c000-000000000000", "00000003-0000-0000-c000-000000000000") // ResourceDisplayName IS NOT Windows Azure Active Directory OR Microsoft Graph
| extend Status = todynamic(Status)
| where Status.errorCode == 0 // Success
| project-reorder IPAddress, UserAgent, ResourceDisplayName, UserDisplayName, UserId, UserPrincipalName, Type
| order by TimeGenerated desc
// New entity mapping
| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
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
  tactics = ['InitialAccess']
  techniques = ['T1078']
  display_name = Azure Active Directory PowerShell accessing non-AAD resources
  description = <<EOT
This will alert when a user or application signs in using Azure Active Directory PowerShell to access non-Active Directory resources, such as the Azure Key Vault, which may be undesired or unauthorized behavior.
For capabilities and expected behavior of the Azure Active Directory PowerShell module, see: https://docs.microsoft.com/powershell/module/azuread/?view=azureadps-2.0.
For further information on Azure Active Directory Signin activity reports, see: https://docs.microsoft.com/azure/active-directory/reports-monitoring/concept-sign-ins.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
