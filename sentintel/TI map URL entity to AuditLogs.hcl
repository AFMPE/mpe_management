resource "my_alert_rule" "rule_7" {
  name = "TI map URL entity to AuditLogs"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P14D
  severity = Medium
  query = <<EOF
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| where Active == true
// Picking up only IOC's that contain the entities we want
| where isnotempty(Url)
// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated
| join kind=innerunique (
  AuditLogs
  | where TimeGenerated >= ago(dt_lookBack)
  // Extract the URL that is contained within the JSON data
  | extend Url = extract("(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+);", 1,tostring(TargetResources))
  | where isnotempty(Url)
  | extend userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend TargetResourceDisplayName = tostring(TargetResources[0].displayName)
  | extend Audit_TimeGenerated = TimeGenerated
) on Url
| where Audit_TimeGenerated < ExpirationDateTime
| summarize Audit_TimeGenerated = arg_max(Audit_TimeGenerated, *) by IndicatorId, Url
| project Audit_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore,
OperationName, Identity, userPrincipalName, TargetResourceDisplayName, Url
| extend timestamp = Audit_TimeGenerated, AccountCustomEntity = userPrincipalName, HostCustomEntity = TargetResourceDisplayName, URLCustomEntity = Url
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
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = URLCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = None
  display_name = TI map URL entity to AuditLogs
  description = <<EOT
Identifies a match in AuditLogs from any URL IOC from TI
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
