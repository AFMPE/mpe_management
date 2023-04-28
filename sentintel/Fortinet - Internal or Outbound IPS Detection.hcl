resource "my_alert_rule" "rule_173" {
  name = "Fortinet - Internal or Outbound IPS Detection"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT10M
  query_period = PT10M
  severity = Medium
  query = <<EOF
CommonSecurityLog
| where DeviceProduct has "Fortigate"
| where Activity has "utm:ips signature"
| where SourceIP matches regex @"(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^127\.)"
| project TimeGenerated, Computer, SourceIP, DestinationIP, AccountCustomEntity = DestinationUserName, Inbound=DeviceInboundInterface, Outbound=DeviceOutboundInterface, Activity, Message, IPCustomEntity = SourceIP
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
  }
  tactics = ['Execution']
  techniques = ['T1059']
  display_name = Fortinet - Internal or Outbound IPS Detection
  description = <<EOT
Alerts when Internal-to-Internal or Internal-to-External traffic triggers our IPS
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
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
