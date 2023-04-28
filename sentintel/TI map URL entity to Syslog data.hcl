resource "my_alert_rule" "rule_248" {
  name = "TI map URL entity to Syslog data"
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
  Syslog
  | where TimeGenerated >= ago(dt_lookBack)
  // Extract URL from the Syslog message but only take messages that include URLs
  | extend Url = extract("(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)", 1,SyslogMessage)
  | where isnotempty(Url)
  | extend Syslog_TimeGenerated = TimeGenerated
) on Url
| where Syslog_TimeGenerated < ExpirationDateTime
| summarize Syslog_TimeGenerated  = arg_max(Syslog_TimeGenerated , *) by IndicatorId, Url
| project Syslog_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, SyslogMessage, Computer, ProcessName, Url, HostIP
| extend timestamp = Syslog_TimeGenerated, HostCustomEntity = Computer, IPCustomEntity = HostIP, URLCustomEntity = Url
EOF
  entity_mapping {
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
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = URLCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = None
  display_name = TI map URL entity to Syslog data
  description = <<EOT
Identifies a match in Syslog data from any URL IOC from TI
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
