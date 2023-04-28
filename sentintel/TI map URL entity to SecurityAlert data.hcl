resource "my_alert_rule" "rule_197" {
  name = "TI map URL entity to SecurityAlert data"
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
  SecurityAlert
  | where TimeGenerated >= ago(dt_lookBack)
  | extend MSTI = case(AlertName has "TI map" and VendorName == "Microsoft" and ProductName == 'Azure Sentinel', true, false)
  | where MSTI == false
  // Extract URL from JSON data
  | extend Url = extract("(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)", 1,Entities)
  // We only want alerts that actually contain URL data
  | where isnotempty(Url)
  // Extract hostname from JSON data for entity mapping
  | extend Compromised_Host = tostring(parse_json(ExtendedProperties).["Compromised Host"])
  | extend Alert_TimeGenerated = TimeGenerated
) on Url
| where Alert_TimeGenerated < ExpirationDateTime
| summarize Alert_TimeGenerated = arg_max(Alert_TimeGenerated, *) by IndicatorId, AlertName
| project Alert_TimeGenerated, ActivityGroupNames, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, AlertName, AlertSeverity, Description, Url, Compromised_Host
| extend timestamp = Alert_TimeGenerated, HostCustomEntity = Compromised_Host, URLCustomEntity = Url
EOF
  entity_mapping {
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
  display_name = TI map URL entity to SecurityAlert data
  description = <<EOT
Identifies a match in SecurityAlert data from any URL IOC from TI
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
