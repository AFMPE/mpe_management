resource "my_alert_rule" "rule_243" {
  name = "Rare application consent"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P7D
  severity = Medium
  query = <<EOF
let current = 1d;
let auditLookback = 7d;
// Setting threshold to 3 as a default, change as needed.  
// Any operation that has been initiated by a user or app more than 3 times in the past 7 days will be excluded
let threshold = 3;
// Gather initial data from lookback period, excluding current, adjust current to more than a single day if no results
let AuditTrail = AuditLogs | where TimeGenerated >= ago(auditLookback) and TimeGenerated < ago(current)
// 2 other operations that can be part of malicious activity in this situation are 
// "Add OAuth2PermissionGrant" and "Add service principal", extend the filter below to capture these too
| where OperationName has "Consent to application"
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| summarize max(TimeGenerated), OperationCount = count() by OperationName, InitiatedBy, TargetResourceName
// only including operations by initiated by a user or app that is above the threshold so we produce only rare and has not occurred in last 7 days
| where OperationCount > threshold
;
// Gather current period of audit data
let RecentConsent = AuditLogs | where TimeGenerated >= ago(current)
| where OperationName has "Consent to application"
| extend IpAddress = case(
isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), 
isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),
'Not Available')
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| parse TargetResources.[0].modifiedProperties with * "ConsentType: " ConsentType "]" *
| mv-expand AdditionalDetails
| extend UserAgent = iff(AdditionalDetails.key == "User-Agent",tostring(AdditionalDetails.value),"")
| project TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type;
// Exclude previously seen audit activity for "Consent to application" that was seen in the lookback period
// First for rare InitiatedBy
let RareConsentBy = RecentConsent | join kind= leftanti AuditTrail on OperationName, InitiatedBy 
| extend Reason = "Previously unseen user consenting";
// Second for rare TargetResourceName
let RareConsentApp = RecentConsent | join kind= leftanti AuditTrail on OperationName, TargetResourceName
| extend Reason = "Previously unseen app granted consent";
RareConsentBy | union RareConsentApp
| summarize Reason = makeset(Reason) by TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatedBy, HostCustomEntity = TargetResourceName, IPCustomEntity = IpAddress
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['Persistence', 'PrivilegeEscalation']
  techniques = ['T1068', 'T1136']
  display_name = Rare application consent
  description = <<EOT
This will alert when the "Consent to application" operation occurs by a user that has not done this operation before or rarely does this.
This could indicate that permissions to access the listed Azure App were provided to a malicious actor. 
Consent to application, Add service principal and Add OAuth2PermissionGrant should typically be rare events. 
This may help detect the Oauth2 attack that can be initiated by this publicly available tool - https://github.com/fireeye/PwnAuth
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.
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
