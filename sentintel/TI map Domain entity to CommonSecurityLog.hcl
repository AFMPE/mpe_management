resource "my_alert_rule" "rule_164" {
  name = "TI map Domain entity to CommonSecurityLog"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P14D
  severity = Medium
  query = <<EOF
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
//Create a list of TLDs in our threat feed for later validation of extracted domains
let list_tlds = ThreatIntelligenceIndicator
| where TimeGenerated > ago(ioc_lookBack)
| where isnotempty(DomainName)
| extend DomainName = tolower(DomainName)
| extend parts = split(DomainName, '.')
| extend tld = parts[(array_length(parts)-1)]
| summarize count() by tostring(tld)
| summarize make_list(tld);
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| where Active == true
// Picking up only IOC's that contain the entities we want
| where isnotempty(DomainName)
// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated
| join kind=innerunique (
   CommonSecurityLog
   | extend IngestionTime = ingestion_time()
   | where IngestionTime > ago(dt_lookBack)
   | where DeviceEventClassID =~ 'url'
   //Uncomment the line below to only alert on allowed connections
   //| where DeviceAction !~ "block-url"
   //Extract domain from RequestURL, if not present extarct it from AdditionalExtentions
   | extend PA_Url = columnifexists("RequestURL", "None")
   | extend PA_Url = iif(isempty(PA_Url) and AdditionalExtensions !startswith "PanOS", extract("([^\"]+)", 1, tolower(AdditionalExtensions)), trim('"', PA_Url))
   | extend PA_Url = iif(PA_Url !startswith "http://" and ApplicationProtocol !~ "ssl", strcat('http://', PA_Url), iif(PA_Url !startswith "https://" and ApplicationProtocol =~ "ssl", strcat('https://', PA_Url), PA_Url))
   | extend Domain = trim(@"""",tostring(parse_url(PA_Url).Host))
   | where isnotempty(Domain)
   | extend Domain = tolower(Domain)
   | extend parts = split(Domain, '.')
   //Split out the TLD for the purpose of checking if we have any TI indicators with this TLD to match on
   | extend tld = parts[(array_length(parts)-1)]
   //Validate parsed domain by checking TLD against TLDs from threat feed and drop domains where there is no chance of a match
   | where tld in~ (list_tlds)
   | extend CommonSecurityLog_TimeGenerated = TimeGenerated
   ) on $left.DomainName==$right.Domain
| where CommonSecurityLog_TimeGenerated < ExpirationDateTime
| summarize CommonSecurityLog_TimeGenerated = arg_max(CommonSecurityLog_TimeGenerated, *) by IndicatorId, FileHashValue
| project CommonSecurityLog_TimeGenerated, Description, ActivityGroupNames, PA_Url, Domain, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, DeviceAction, DestinationIP, DestinationPort, DeviceName, SourceIP, SourcePort, ApplicationProtocol, RequestMethod
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
  display_name = TI map Domain entity to CommonSecurityLog
  description = <<EOT
Identifies a match in CommonSecurityLog table from any Domain IOC from TI
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
