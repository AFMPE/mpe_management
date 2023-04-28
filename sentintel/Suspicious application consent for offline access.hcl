resource "my_alert_rule" "rule_338" {
  name = "Suspicious application consent for offline access"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Low
  query = <<EOF
let detectionTime = 1d;
let joinLookback = 14d;
AuditLogs
| where TimeGenerated > ago(detectionTime)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application"
| where TargetResources has "offline"
| extend AppDisplayName = TargetResources.[0].displayName
| extend AppClientId = tolower(TargetResources.[0].id)
| where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayName:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv")))
| extend ConsentFull = TargetResources[0].modifiedProperties[4].newValue
| parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1 "]" *
| where ConsentFull contains "offline_access" and ConsentFull contains "Files.Read" or ConsentFull contains "Mail.Read" or ConsentFull contains "Notes.Read" or ConsentFull contains "ChannelMessage.Read" or ConsentFull contains "Chat.Read" or ConsentFull contains "TeamsActivity.Read" or ConsentFull contains "Group.Read" or ConsentFull contains "EWS.AccessAsUser.All" or ConsentFull contains "EAS.AccessAsUser.All"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = tostring(iff(isnotempty(InitiatedBy.user.ipAddress), InitiatedBy.user.ipAddress, InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = tostring(iff(isnotempty(InitiatedBy.user.userPrincipalName),InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName))
| extend GrantUserAgent = tostring(iff(AdditionalDetails[0].key =~ "User-Agent", AdditionalDetails[0].value, ""))
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, GrantIpAddress, GrantUserAgent, AppClientId, OperationName, ConsentFull, CorrelationId
| join kind = leftouter (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add service principal"
| extend AppClientId = tolower(TargetResources[0].id)
| extend AppReplyURLs = iff(TargetResources[0].modifiedProperties[1].newValue has "AddressType", TargetResources[0].modifiedProperties[1].newValue, "")
| distinct AppClientId, tostring(AppReplyURLs)
)
on AppClientId
| join kind = innerunique (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add OAuth2PermissionGrant" or OperationName =~ "Add delegated permission grant"
| extend GrantAuthentication = tostring(TargetResources[0].displayName)
| extend GrantOperation = OperationName
| project GrantAuthentication, GrantOperation, CorrelationId
) on CorrelationId
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, AppReplyURLs, GrantIpAddress, GrantUserAgent, AppClientId, GrantAuthentication, OperationName, GrantOperation, CorrelationId, ConsentFull
| extend timestamp = TimeGenerated, AccountCustomEntity = GrantInitiatedBy, IPCustomEntity = GrantIpAddress
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
  tactics = ['CredentialAccess']
  techniques = ['T1528']
  display_name = Suspicious application consent for offline access
  description = <<EOT
This will alert when a user consents to provide a previously-unknown Azure application with offline access via OAuth.
Offline access will provide the Azure App with access to the listed resources without requiring two-factor authentication.
Consent to applications with offline access and read capabilities should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.
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
