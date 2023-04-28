resource "my_alert_rule" "rule_28" {
  name = "TI map URL entity to PaloAlto data"
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
  CommonSecurityLog
  | extend IngestionTime = ingestion_time()
  | where IngestionTime > ago(dt_lookBack)
  // Select on Palo Alto logs
  | where DeviceVendor =~ "Palo Alto Networks"
  | where DeviceEventClassID =~ 'url'
  //Uncomment the line below to only alert on allowed connections
  //| where DeviceAction !~ "block-url"
  //Select logs where URL data is populated
  | extend PA_Url = columnifexists("RequestURL", "None")
  | extend PA_Url = iif(isempty(PA_Url), extract("([^\"]+)", 1, tolower(AdditionalExtensions)), trim('"', PA_Url))
  | extend PA_Url = iif(PA_Url !startswith "http://" and ApplicationProtocol !~ "ssl", strcat('http://', PA_Url), iif(PA_Url !startswith "https://" and ApplicationProtocol =~ "ssl", strcat('https://', PA_Url), PA_Url))
  | where isnotempty(PA_Url)
  | extend CommonSecurityLog_TimeGenerated = TimeGenerated
) on $left.Url == $right.PA_Url
| where CommonSecurityLog_TimeGenerated < ExpirationDateTime
| summarize CommonSecurityLog_TimeGenerated = arg_max(CommonSecurityLog_TimeGenerated, *) by IndicatorId, PA_Url
| project CommonSecurityLog_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, DeviceAction, SourceIP, PA_Url, DeviceName
| extend timestamp = CommonSecurityLog_TimeGenerated, IPCustomEntity = SourceIP, HostCustomEntity = DeviceName, URLCustomEntity = PA_Url
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
  display_name = TI map URL entity to PaloAlto data
  description = <<EOT
Identifies a match in PaloAlto data from any URL IOC from TI
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
