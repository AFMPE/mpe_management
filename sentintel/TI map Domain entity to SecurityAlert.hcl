resource "my_alert_rule" "rule_350" {
  name = "TI map Domain entity to SecurityAlert"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P14D
  severity = Medium
  query = <<EOF
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
//Create a list of TLDs in our threat feed for later validation
let list_tlds = ThreatIntelligenceIndicator
| where TimeGenerated > ago(ioc_lookBack)
| where isnotempty(DomainName)
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
    SecurityAlert
    | where TimeGenerated > ago(dt_lookBack)
    | extend MSTI = case(AlertName has "TI map" and VendorName == "Microsoft" and ProductName == 'Azure Sentinel', true, false)
    | where MSTI == false
    //Extract domain patterns from message
    | extend domain = extract("(([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,})", 1, tolower(Entities))
    | where isnotempty(domain)
    | extend parts = split(domain, '.')
    //Split out the TLD
    | extend tld = parts[(array_length(parts)-1)]
    //Validate parsed domain by checking if the TLD is in the list of TLDs in our threat feed
    | where tld in~ (list_tlds)
    // Converting Entities into dynamic data type and use mv-expand to unpack the array
    | extend EntitiesDynamicArray = parse_json(Entities) | mv-expand EntitiesDynamicArray
    // Parsing relevant entity column extract hostname and IP address
    | extend EntityType = tostring(parse_json(EntitiesDynamicArray).Type), EntityAddress = tostring(EntitiesDynamicArray.Address), EntityHostName = tostring(EntitiesDynamicArray.HostName)
    | extend HostName = iif(EntityType == 'host', EntityHostName, '')
    | extend IP_addr = iif(EntityType == 'ip', EntityAddress, '')
    | extend Alert_TimeGenerated = TimeGenerated
    | extend Alert_Description = Description
) on $left.DomainName==$right.domain
| where Alert_TimeGenerated < ExpirationDateTime
| summarize Alert_TimeGenerated = arg_max(Alert_TimeGenerated, *) by IndicatorId, AlertName
| project Alert_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, AlertName, Alert_Description, ProviderName, AlertSeverity, ConfidenceLevel, HostName, IP_addr, Url
| extend timestamp = Alert_TimeGenerated, HostCustomEntity = HostName, IPCustomEntity = IP_addr, URLCustomEntity = Url
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
  display_name = TI map Domain entity to SecurityAlert
  description = <<EOT
Identifies a match in SecurityAlert table from any Domain IOC from TI
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
