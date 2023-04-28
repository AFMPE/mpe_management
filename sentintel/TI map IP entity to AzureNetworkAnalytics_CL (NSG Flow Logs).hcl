resource "my_alert_rule" "rule_271" {
  name = "TI map IP entity to AzureNetworkAnalytics_CL (NSG Flow Logs)"
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
| where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempty(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
// As there is potentially more than 1 indicator type for matching IP, taking NetworkIP first, then others if that is empty.
// Taking the first non-empty value based on potential IOC match availability
| extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinationIP)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP), NetworkSourceIP, TI_ipEntity)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAddress), EmailSourceIpAddress, TI_ipEntity)
// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated
| join kind=innerunique (
    AzureNetworkAnalytics_CL
    | where TimeGenerated >= ago(dt_lookBack)
    // renaming time column so it is clear the log this came from
    | extend AzureNetworkAnalytics_CL_TimeGenerated = TimeGenerated
    // NSG Flow Logs have additional information concat with Public IP, removing onlp Public IP
    | extend PIPs = split(PublicIPs_s, '|', 0)
    | extend PIP = tostring(PIPs[0])
)
on $left.TI_ipEntity == $right.PIP
| where AzureNetworkAnalytics_CL_TimeGenerated < ExpirationDateTime
| summarize AzureNetworkAnalytics_CL_TimeGenerated = arg_max(AzureNetworkAnalytics_CL_TimeGenerated, *) by IndicatorId, PIP
// Set to alert on Allowed NSG Flows from TI Public IP IOC
| where FlowStatus_s == "A"
| project AzureNetworkAnalytics_CL_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
TI_ipEntity, Computer, FlowDirection_s, FlowStatus_s, FlowType_s, SrcPublicIPs_s, DestPublicIPs_s, PublicIPs_s, L7Protocol_s, DestPort_d, NetworkIP, NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress
| extend timestamp = AzureNetworkAnalytics_CL_TimeGenerated, IPCustomEntity = TI_ipEntity, HostCustomEntity = Computer, URLCustomEntity = Url
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
  display_name = TI map IP entity to AzureNetworkAnalytics_CL (NSG Flow Logs)
  description = <<EOT
Identifies a match in AzureNetworkAnalytics_CL (NSG Flow Logs) from any IP IOC from TI that was Allowed
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
