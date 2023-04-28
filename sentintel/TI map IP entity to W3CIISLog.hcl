resource "my_alert_rule" "rule_370" {
  name = "TI map IP entity to W3CIISLog"
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
//Exclude local addresses, using the ipv4_is_private operator
| where ipv4_is_private(TI_ipEntity) == false and  TI_ipEntity !startswith "fe80" and TI_ipEntity !startswith "::" and TI_ipEntity !startswith "127."
// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated
| join kind=innerunique (
    W3CIISLog
    | where TimeGenerated >= ago(dt_lookBack)
    | where isnotempty(cIP)
    //Exclude local addresses, using the ipv4_is_private operator
    | where ipv4_is_private(cIP) == false and  cIP !startswith "fe80" and cIP !startswith "::" and cIP !startswith "127."
    // renaming time column so it is clear the log this came from
    | extend W3CIISLog_TimeGenerated = TimeGenerated
)
on $left.TI_ipEntity == $right.cIP
| where W3CIISLog_TimeGenerated < ExpirationDateTime
| summarize W3CIISLog_TimeGenerated = arg_max(W3CIISLog_TimeGenerated, *) by IndicatorId, cIP
| project W3CIISLog_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
TI_ipEntity, Computer, sSiteName, cIP, sIP, sPort, csMethod, csUserName, scStatus, scSubStatus, scWin32Status,
NetworkIP, NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress
| extend timestamp = W3CIISLog_TimeGenerated, IPCustomEntity = cIP, HostCustomEntity = Computer, AccountCustomEntity = csUserName, URLCustomEntity = Url
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
  display_name = TI map IP entity to W3CIISLog
  description = <<EOT
Identifies a match in W3CIISLog from any IP IOC from TI
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
