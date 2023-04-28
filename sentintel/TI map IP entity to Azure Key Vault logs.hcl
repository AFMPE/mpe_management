resource "my_alert_rule" "rule_275" {
  name = "TI map IP entity to Azure Key Vault logs"
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
       | where ResourceType =~ "VAULTS"
       | where TimeGenerated >= ago(dt_lookBack)
       | extend KeyVaultEvents_TimeGenerated = TimeGenerated, ClientIP = CallerIPAddress
)
on $left.TI_ipEntity == $right.ClientIP
| where KeyVaultEvents_TimeGenerated < ExpirationDateTime
| summarize KeyVaultEvents_TimeGenerated = arg_max(KeyVaultEvents_TimeGenerated, *) by IndicatorId, ClientIP
| project KeyVaultEvents_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
TI_ipEntity, ClientIP, ResourceId, SubscriptionId, OperationName, ResultType, CorrelationId, id_s, clientInfo_s, httpStatusCode_d, identity_claim_appid_g, identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g
| extend timestamp = KeyVaultEvents_TimeGenerated
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = ClientIP
    }
    entity_type = AzureResource
    field_mappings {
      identifier = ResourceId
      column_name = ResourceId
    }
  }
  tactics = ['Impact']
  techniques = None
  display_name = TI map IP entity to Azure Key Vault logs
  description = <<EOT
Identifies a match in Azure Key Vault logsfrom any IP IOC from TI
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
