resource "my_alert_rule" "rule_302" {
  name = "HAFNIUM Suspicious UM Service Error"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
Event
| where EventLog =~ "Application"
| where Source startswith "MSExchange"
| where EventLevelName =~ "error"
| where (RenderedDescription startswith "Watson report" and RenderedDescription contains "umworkerprocess" and RenderedDescription contains "TextFormattingRunProperties") or RenderedDescription startswith "An unhandled exception occurred in a UM worker process" or RenderedDescription startswith "The Microsoft Exchange Unified Messaging service" or RenderedDescription contains "MSExchange Unified Messaging"
| where RenderedDescription !contains "System.OutOfMemoryException"
| extend timestamp = TimeGenerated, HostCustomEntity = Computer
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
  }
  tactics = ['InitialAccess']
  techniques = ['T1190']
  display_name = HAFNIUM Suspicious UM Service Error
  description = <<EOT
This query looks for errors that may indicate that an attacker is attempting to exploit a vulnerability in the service. 
Reference: https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
