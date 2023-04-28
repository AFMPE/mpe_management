resource "my_alert_rule" "rule_178" {
  name = "Palo Alto Threat Detected and Allowed"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT30M
  query_period = PT30M
  severity = Medium
  query = <<EOF
CommonSecurityLog
| where Activity has "THREAT"
| where DeviceAction has_any ("alert", "allow")
| where LogSeverity has_any ("4", "5")
| extend ThreatCategory = extract("PanOSThreatCategory=(.+?);",1,AdditionalExtensions)
| project TimeGenerated, Severity = LogSeverity, ThreatCategory, Description = DeviceEventClassID, SourceIP, DestinationIP, DestinationPort, DestinationTranslatedAddress, DeviceAction
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = DestinationIP
    }
  }
  tactics = ['InitialAccess', 'Execution']
  techniques = ['T1059']
  display_name = Palo Alto - Threat Detected and Allowed
  description = <<EOT

EOT
  enabled = False
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
