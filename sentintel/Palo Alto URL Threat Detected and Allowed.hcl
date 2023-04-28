resource "my_alert_rule" "rule_150" {
  name = "Palo Alto URL Threat Detected and Allowed"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT15M
  query_period = PT15M
  severity = Low
  query = <<EOF
CommonSecurityLog
| where Activity has "THREAT"
| where DeviceEventClassID has "url"
| where DeviceAction has_any ("alert", "allow")
| where LogSeverity has_any ("4", "5")
| where DeviceCustomString2 !has "low-risk"
| where not(SourceUserName has_any("qualysgaming.svc", "qualys.svc", "opsmgr.service", "wmiq.service"))
| project TimeGenerated, Severity = LogSeverity, ApplicationProtocol, URL_Category = DeviceCustomString2, SourceIP, SourceZone = DeviceCustomString4, DestinationTranslatedAddress, DestinationIP, DestinationPort, DestinationSourceZone = DeviceCustomString5, DeviceAction, SourceUserName
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = SourceUserName
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = SourceIP
    }
  }
  tactics = ['InitialAccess', 'Execution']
  techniques = ['T1059', 'T1566']
  display_name = Palo Alto URL Threat Detected and Allowed
  description = <<EOT
This rule alerts when URL based threats are allowed through the firewall. 
EOT
  enabled = True
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
