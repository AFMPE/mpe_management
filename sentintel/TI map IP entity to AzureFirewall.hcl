resource "my_alert_rule" "rule_291" {
  name = "TI map IP entity to AzureFirewall"
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
    AzureDiagnostics
    | where TimeGenerated >= ago(dt_lookBack)
    | where OperationName in ("AzureFirewallApplicationRuleLog", "AzureFirewallNetworkRuleLog")
    | parse kind=regex flags=U msg_s with Protocol 'request from ' SourceHost 'to ' DestinationHost @'\.? Action: ' Firewall_Action @'\.' Rest_msg
    | extend SourceAddress = extract(@'([\.0-9]+)(:[\.0-9]+)?', 1, SourceHost)
    | extend DestinationAddress = extract(@'([\.0-9]+)(:[\.0-9]+)?', 1, DestinationHost)
    | extend RemoteIP = case(not(ipv4_is_private(DestinationAddress)), DestinationAddress, not(ipv4_is_private(SourceAddress)), SourceAddress, "")
    // Traffic that involves a public address, and in case this is the source address then the traffic was not denied
    | where isnotempty(RemoteIP)
    | project-rename AzureFirewall_TimeGenerated = TimeGenerated
)
on $left.TI_ipEntity == $right.RemoteIP
| where AzureFirewall_TimeGenerated < ExpirationDateTime
| summarize AzureFirewall_TimeGenerated = arg_max(AzureFirewall_TimeGenerated, *) by IndicatorId, RemoteIP
| project LatestIndicatorTime, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, DomainName, ExpirationDateTime, ConfidenceScore, AzureFirewall_TimeGenerated,
TI_ipEntity, Resource, Category, msg_s, SourceAddress, DestinationAddress, Firewall_Action, Protocol, NetworkIP, NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress
| extend timestamp = AzureFirewall_TimeGenerated, IPCustomEntity = TI_ipEntity, URLCustomEntity = Url
EOF
  entity_mapping {
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
  display_name = TI map IP entity to AzureFirewall
  description = <<EOT
Identifies a match in AzureFirewall (NetworkRule & ApplicationRule Logs) from any IP IOC from TI
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
