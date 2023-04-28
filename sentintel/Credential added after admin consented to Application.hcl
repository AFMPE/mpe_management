resource "my_alert_rule" "rule_121" {
  name = "Credential added after admin consented to Application"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P2D
  severity = Medium
  query = <<EOF
let auditLookbackStart = 2d;
let auditLookbackEnd = 1d;
AuditLogs
| where TimeGenerated >= ago(auditLookbackStart)
| where OperationName =~ "Consent to application" 
| where Result =~ "success"
| mv-expand target = TargetResources
| extend targetResourceName = tostring(target.displayName)
| extend targetResourceID = tostring(target.id)
| extend targetResourceType = tostring(target.type)
| extend targetModifiedProp = TargetResources[0].modifiedProperties
| extend isAdminConsent = targetModifiedProp[0].newValue
| extend Consent_ServicePrincipalNames = targetModifiedProp[5].newValue
| extend Consent_Permissions = targetModifiedProp[4].newValue
| extend Consent_InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend Consent_InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| join ( 
AuditLogs
| where TimeGenerated  >= ago(auditLookbackEnd)
| where OperationName =~ "Add service principal credentials"
| where Result =~ "success"
| mv-expand target = TargetResources
| extend targetResourceName = tostring(target.displayName)
| extend targetResourceID = tostring(target.id)
| extend targetModifiedProp = TargetResources[0].modifiedProperties
| extend Credential_KeyDescription = targetModifiedProp[0].newValue
| extend UpdatedProperties = targetModifiedProp[1].newValue
| extend Credential_ServicePrincipalNames = targetModifiedProp[2].newValue
| extend Credential_InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend Credential_InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
) on targetResourceName, targetResourceID
| extend TimeConsent = TimeGenerated, TimeCred = TimeGenerated1
| where TimeConsent > TimeCred 
| project TimeConsent, TimeCred, Consent_InitiatingUserOrApp, Credential_InitiatingUserOrApp, targetResourceName, targetResourceType, isAdminConsent, Consent_ServicePrincipalNames, Credential_ServicePrincipalNames, Consent_Permissions, Credential_KeyDescription, Consent_InitiatingIpAddress, Credential_InitiatingIpAddress
| extend timestamp = TimeConsent, AccountCustomEntity = Consent_InitiatingUserOrApp, IPCustomEntity = Consent_InitiatingIpAddress
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
  tactics = ['Persistence']
  techniques = ['T1098']
  display_name = Credential added after admin consented to Application
  description = <<EOT
This query will identify instances where Service Principal credentials were added to an application by one user after the application was granted admin consent rights by another user.
 If a threat actor obtains access to an account with sufficient privileges and adds the alternate authentication material triggering this event, the threat actor can now authenticate as the Application or Service Principal using this credential.
 Additional information on OAuth Credential Grants can be found in RFC 6749 Section 4.4 or https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow.
 For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities
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
