resource "my_alert_rule" "rule_6" {
  name = "TOR Activity Detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT15M
  query_period = PT15M
  severity = Low
  query = <<EOF
let TorRelayData = (
externaldata (Nickname:string,Fingerprint:string,EntryAddress:string,IPAddress:string,Port:string,AddressType:string,Hostname:string,CountryCode:string,IsRunning:bool,RelayPublishDate:string,LastChangedIPData:string)[h@'https://torinfo.blob.core.windows.net/public/TorRelayIPs.csv'] with (ignoreFirstRecord=true,format="csv")
| project IPAddress, Port
);
union(
TorRelayData
| join kind=inner (CommonSecurityLog | extend Port = tostring(DestinationPort)) on $left.IPAddress == $right.DestinationIP and $left.Port == $right.Port
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, DeviceProduct, Computer, ApplicationProtocol
),
(TorRelayData
| join kind=inner (DeviceNetworkEvents | extend Port = tostring(RemotePort)) on $left.IPAddress == $right.RemoteIP and $left.Port == $right.Port
| project TimeGenerated, DeviceId, DeviceName, Account = InitiatingProcessAccountName, SourceIP=LocalIP, DestinationIP=RemoteIP, Action=ActionType, InitiatingProcessFileName, FolderPath=InitiatingProcessFolderPath, CommandLine = InitiatingProcessCommandLine
),
(DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "meek-client.exe")
| project TimeGenerated, DeviceId, DeviceName, Account = InitiatingProcessAccountName, SourceIP=LocalIP, DestinationIP=RemoteIP, Action=ActionType, InitiatingProcessFileName, FolderPath=InitiatingProcessFolderPath, CommandLine = InitiatingProcessCommandLine
),
(SecurityEvent
| where EventID == "4688"
| where ProcessName has_any ("tor.exe", "meek-client.exe")
| project TimeGenerated, DeviceId, DeviceName = Computer, Account, CommandLine
)
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = DeviceName
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = SourceIP
    }
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = CommandLine
    }
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = InitiatingProcessFileName
    }
  }
  tactics = ['CommandAndControl']
  techniques = ['T1573']
  display_name = TOR Activity Detected
  description = <<EOT
This rule detects the use of tor.exe/meek-client.exe in the environment. It also detects when outbound network traffic interacts with a known TOR relay IP. The relay IP's are updated every 12 hours from the official TOR relay list. 
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
