resource "my_alert_rule" "rule_255" {
  name = "TI map IP entity to CommonSecurityLog"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P14D
  severity = Medium
  query = <<EOF
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
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
    CommonSecurityLog
    | where TimeGenerated >= ago(dt_lookBack)
    | extend MessageIP = extract(IPRegex, 0, Message)
    | extend CS_ipEntity = iff(isnotempty(SourceIP), SourceIP, DestinationIP)
    | extend CS_ipEntity = iff(isempty(CS_ipEntity) and isnotempty(MessageIP), MessageIP, CS_ipEntity)
    | extend CommonSecurityLog_TimeGenerated = TimeGenerated
)
on $left.TI_ipEntity == $right.CS_ipEntity
| where CommonSecurityLog_TimeGenerated < ExpirationDateTime
| summarize CommonSecurityLog_TimeGenerated = arg_max(CommonSecurityLog_TimeGenerated, *) by IndicatorId, CS_ipEntity
| project CommonSecurityLog_TimeGenerated, SourceIP, DestinationIP, MessageIP, Message, DeviceVendor, DeviceProduct, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, TI_ipEntity, CS_ipEntity, LogSeverity, DeviceAction
| extend timestamp = CommonSecurityLog_TimeGenerated, IPCustomEntity = CS_ipEntity
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = None
  display_name = TI map IP entity to CommonSecurityLog
  description = <<EOT
Identifies a match in CommonSecurityLog from any IP IOC from TI
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
