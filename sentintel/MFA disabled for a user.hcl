resource "my_alert_rule" "rule_125" {
  name = "MFA disabled for a user"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
(union isfuzzy=true
(AuditLogs 
| where OperationName =~ "Disable Strong Authentication"
| extend IPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) 
| extend InitiatedByUser = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
 tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend Targetprop = todynamic(TargetResources)
| extend TargetUser = tostring(Targetprop[0].userPrincipalName) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by User = TargetUser, InitiatedByUser , Operation = OperationName , CorrelationId, IPAddress, Category, Source = SourceSystem , AADTenantId, Type
),
(AWSCloudTrail
| where EventName in~ ("DeactivateMFADevice", "DeleteVirtualMFADevice") 
| extend InstanceProfileName = tostring(parse_json(RequestParameters).InstanceProfileName)
| extend TargetUser = tostring(parse_json(RequestParameters).userName)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by User = TargetUser, Source = EventSource , Operation = EventName , TenantorInstance_Detail = InstanceProfileName, IPAddress = SourceIpAddress
)
)
| extend timestamp = StartTimeUtc, AccountCustomEntity = User, IPCustomEntity = IPAddress
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
  techniques = ['T1111']
  display_name = MFA disabled for a user
  description = <<EOT
Multi-Factor Authentication (MFA) helps prevent credential compromise. This alert identifies when an attempt has been made to disable MFA for a user 
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
