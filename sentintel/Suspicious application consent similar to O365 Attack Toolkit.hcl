resource "my_alert_rule" "rule_133" {
  name = "Suspicious application consent similar to O365 Attack Toolkit"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = High
  query = <<EOF
let detectionTime = 1d;
let joinLookback = 14d;
AuditLogs
| where TimeGenerated > ago(detectionTime)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application"
| where TargetResources has "mailboxsettings"
| extend AppDisplayName = TargetResources.[0].displayName
| extend AppClientId = tolower(TargetResources.[0].id)
| where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayName:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv")))
| extend ConsentFull = TargetResources[0].modifiedProperties[4].newValue
| parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1 "]" *
| where ConsentFull contains "contacts.read" and ConsentFull contains "user.read" and ConsentFull contains "mail.read" and ConsentFull contains "notes.read.all" and ConsentFull contains "mailboxsettings.readwrite" and ConsentFull contains "Files.ReadWrite.All"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", tostring(AdditionalDetails[0].value), "")
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
  tactics = ['CredentialAccess', 'DefenseEvasion']
  techniques = ['T1528', 'T1550']
  display_name = Suspicious application consent similar to O365 Attack Toolkit
  description = <<EOT
This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the MDSec O365 Attack Toolkit (https://github.com/mdsecactivebreach/o365-attack-toolkit).
The default permissions/scope for the MDSec O365 Attack toolkit are contacts.read, user.read, mail.read, notes.read.all, mailboxsettings.readwrite, and files.readwrite.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
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
