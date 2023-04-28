resource "my_alert_rule" "rule_209" {
  name = "TI map IP entity to Duo Security"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P14D
  severity = Medium
  query = <<EOF
let dt_lookBack = 1h;
let ioc_lookBack = 14d;
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| where Active == true
// Picking up only IOC's that contain the entities we want
| where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempty(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
// As there is potentially more than 1 indicator type for matching IP, taking NetworkIP first, then others if that is empty.
// Taking the first non-empty value based on potential IOC match availability
| extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinationIP)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP), NetworkSourceIP, TI_ipEntity)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAddress), EmailSourceIpAddress, TI_ipEntity)
| join (
    DuoSecurityAuthentication_CL
    | where TimeGenerated >= ago(dt_lookBack)
    | where isnotempty(access_device_ip_s)
    // renaming time column so it is clear the log this came from
    | extend Duo_TimeGenerated = isotimestamp_t
)
on $left.TI_ipEntity == $right.access_device_ip_s
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| project LatestIndicatorTime, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore, Duo_TimeGenerated,
TI_ipEntity, user_name_s, factor_s, result_s, application_name_s, event_type_s, txid_g, user_key_s, access_device_ip_s, access_device_location_city_s, access_device_location_state_s, access_device_location_country_s
| extend timestamp = Duo_TimeGenerated, IPCustomEntity = access_device_ip_s, AccountCustomEntity = user_name_s
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = None
  display_name = TI map IP entity to Duo Security
  description = <<EOT
Identifies a match in DuoSecurity from any IP IOC from TI
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
