resource "my_alert_rule" "rule_252" {
  name = "TI map URL entity to OfficeActivity data"
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
  OfficeActivity
  | where TimeGenerated >= ago(dt_lookBack)
  //Extract the Url from a number of potential fields
  | extend Url = iif(OfficeWorkload == "AzureActiveDirectory",extract("(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+);", 1,ModifiedProperties),tostring(parse_json(ModifiedProperties)[12].NewValue))
  | where isnotempty(Url)
  // Ensure we get a clean URL
  | extend Url = tostring(split(Url, ';')[0])
  | extend OfficeActivity_TimeGenerated = TimeGenerated
  // Project a single user identity that we can use for entity mapping
  | extend User = iif(isnotempty(UserId), UserId, iif(isnotempty(Actor), tostring(parse_json(Actor)[0].ID), tostring(parse_json(Parameters)[0].Value)))
) on Url
| where OfficeActivity_TimeGenerated < ExpirationDateTime
| summarize OfficeActivity_TimeGenerated = arg_max(OfficeActivity_TimeGenerated, *) by IndicatorId, Url
| project OfficeActivity_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, Operation, 
UserType, OfficeWorkload, Parameters, Url, User
| extend timestamp = OfficeActivity_TimeGenerated, AccountCustomEntity = User, URLCustomEntity = Url
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = URLCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = None
  display_name = TI map URL entity to OfficeActivity data
  description = <<EOT
Identifies a match in OfficeActivity data from any URL IOC from TI
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
