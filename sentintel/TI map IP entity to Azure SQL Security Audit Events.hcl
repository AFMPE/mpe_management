resource "my_alert_rule" "rule_174" {
  name = "TI map IP entity to Azure SQL Security Audit Events"
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
| where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempty(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
| extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinationIP)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP), NetworkSourceIP, TI_ipEntity)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAddress), EmailSourceIpAddress, TI_ipEntity)
// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated
| join kind=innerunique (
      AzureDiagnostics
      | where TimeGenerated >= ago(dt_lookBack)
      | where ResourceProvider == 'MICROSOFT.SQL'
      | where Category == 'SQLSecurityAuditEvents'
      | extend SQLSecurityAuditEvents_TimeGenerated = TimeGenerated
      // projecting fields with column if exists as this is in AzureDiag and if the event is not in the table, then queries will fail due to event specific schemas
      | extend ClientIP = column_ifexists("client_ip_s", "Not Available"), Action = column_ifexists("action_name_s", "Not Available"), 
      Application = column_ifexists("application_name_s", "Not Available"), HostName = column_ifexists("host_name_s", "Not Available")
)
on $left.TI_ipEntity == $right.ClientIP
| where SQLSecurityAuditEvents_TimeGenerated < ExpirationDateTime
| summarize SQLSecurityAuditEvents_TimeGenerated = arg_max(SQLSecurityAuditEvents_TimeGenerated, *) by IndicatorId, ClientIP
| project SQLSecurityAuditEvents_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
TI_ipEntity, ResourceId, ClientIP, Action, Application, HostName, NetworkIP, NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress
| extend timestamp = SQLSecurityAuditEvents_TimeGenerated
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = ClientIP
    }
  }
  tactics = ['Impact']
  techniques = None
  display_name = TI map IP entity to Azure SQL Security Audit Events
  description = <<EOT
Identifies a match in SQLSecurityAuditEvents from any IP IOC from TI
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
