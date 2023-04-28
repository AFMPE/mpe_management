resource "my_alert_rule" "rule_40" {
  name = "Modified domain federation trust settings"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
(union isfuzzy=true
(
AuditLogs
| where OperationName =~ "Set federation settings on domain"
//| where Result =~ "success"   // commenting out, as it may be interesting to capture failed attempts
| mv-expand TargetResources
| extend modifiedProperties = parse_json(TargetResources).modifiedProperties
| mv-expand modifiedProperties
| extend targetDisplayName = tostring(parse_json(modifiedProperties).displayName)
| mv-expand AdditionalDetails
),
(
AuditLogs
| where OperationName =~ "Set domain authentication"
//| where Result =~ "success"   // commenting out, as it may be interesting to capture failed attempts
| mv-expand TargetResources
| extend modifiedProperties = parse_json(TargetResources).modifiedProperties
| mv-expand modifiedProperties
| extend targetDisplayName = tostring(parse_json(modifiedProperties).displayName), NewDomainValue=tostring(parse_json(modifiedProperties).newValue)
| where NewDomainValue has "Federated"
)
)
| extend UserAgent = iff(AdditionalDetails.key == "User-Agent",tostring(AdditionalDetails.value),"")
| extend InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| project-reorder TimeGenerated, OperationName, InitiatingUserOrApp, AADOperationType, targetDisplayName, Result, InitiatingIpAddress, UserAgent, CorrelationId, TenantId, AADTenantId
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingUserOrApp, IPCustomEntity = InitiatingIpAddress
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
  techniques = ['T1555']
  display_name = Modified domain federation trust settings
  description = <<EOT
This will alert when a user or application modifies the federation settings on the domain or Update domain authentication from Managed to Federated.
For example, this alert will trigger when a new Active Directory Federated Service (ADFS) TrustedRealm object, such as a signing certificate, is added to the domain.
Modification to domain federation settings should be rare. Confirm the added or modified target domain/URL is legitimate administrator behavior.
To understand why an authorized user may update settings for a federated domain in Office 365, Azure, or Intune, see: https://docs.microsoft.com/office365/troubleshoot/active-directory/update-federated-domain-office-365.
For details on security realms that accept security tokens, see the ADFS Proxy Protocol (MS-ADFSPP) specification: https://docs.microsoft.com/openspecs/windows_protocols/ms-adfspp/e7b9ea73-1980-4318-96a6-da559486664b.
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
