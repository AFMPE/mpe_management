resource "my_alert_rule" "rule_242" {
  name = "Direct Outbound SMB Connection"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = High
  query = <<EOF
let CSL = (CommonSecurityLog
| where DestinationPort == 445
| where SourceIP  matches regex @"(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)"
| where not(DestinationIP  matches regex @"(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)")
| where DeviceInboundInterface != DeviceOutboundInterface
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, DeviceAction, DeviceInboundInterface, DeviceOutboundInterface, Computer
);
let DFE = (DeviceNetworkEvents
| where RemotePort == 445
| where LocalIP  matches regex @"(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)"
| where not(RemoteIP  matches regex @"(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)")
| project TimeGenerated, SourceIP = LocalIP, DestinationIP = RemoteIP, DestinationPort = RemotePort, Computer = DeviceName, DeviceAction = ActionType, RemoteUrl
);
CSL
| union DFE
| extend IpCustomEntity = SourceIP
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = SourceIP
    }
  }
  tactics = ['LateralMovement']
  techniques = ['T1021']
  display_name = Direct Outbound SMB Connection
  description = <<EOT
'Identifies unexpected processes making network connections over port 445. Windows File Sharing is typically implemented over Server Message Block (SMB), which communicates between hosts using port 445. When legitimate, these network connections are established by the kernel. Processes making 445/tcp connections may be port scanners, exploits, or suspicious user-level processes moving laterally.'

EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
