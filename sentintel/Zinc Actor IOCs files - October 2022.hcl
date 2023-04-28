resource "my_alert_rule" "rule_76" {
  name = "Zinc Actor IOCs files - October 2022"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT6H
  query_period = PT6H
  severity = High
  query = <<EOF
let iocs = externaldata(DateAdded:string,IoC:string,Type:string) [@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/ZincOctober2022IOCs.csv"] with (format="csv", ignoreFirstRecord=True);
let file_path = (iocs | where Type =~ "filepath" | project IoC);
let commandline = (iocs | where Type =~ "commandline" | project IoC);
(union isfuzzy=true 
(DeviceNetworkEvents
| where  InitiatingProcessFolderPath has_any (file_path) or InitiatingProcessCommandLine has_any (commandline)
| project TimeGenerated, ActionType, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, RemoteIP, RemoteUrl, LocalIP, Type
| extend timestamp = TimeGenerated, IPCustomEntity = RemoteIP, HostCustomEntity = DeviceName, UrlCustomEntity =RemoteUrl
),
(Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| extend Image = EventDetail.[4].["#text"],  CommandLine = EventDetail.[10].["#text"]
| where Image has_any (file_path)  or   CommandLine has_any (commandline)
| project TimeGenerated, EventDetail, UserName, Computer, Type, Source, CommandLine, Image
| extend Type = strcat(Type, ": ", Source)
| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = UserName, ProcessCustomEntity = tostring(split(Image, '\\', -1)[-1])
),  
(DeviceProcessEvents
| where  ( InitiatingProcessCommandLine has_any (file_path)) or ( InitiatingProcessCommandLine has_any (commandline))  or (InitiatingProcessFolderPath has_any (file_path)) or (InitiatingProcessFolderPath has_any (commandline)) or (FolderPath  has_any (file_path)) or (FolderPath has_any (commandline))
| project TimeGenerated, ActionType, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessSHA256, FolderPath, Type
| extend timestamp = TimeGenerated, HostCustomEntity = DeviceName , AccountCustomEntity = InitiatingProcessAccountName, ProcessCustomEntity = InitiatingProcessFileName
),
(DeviceFileEvents
| where  (InitiatingProcessFolderPath has_any (file_path)) or (InitiatingProcessFolderPath has_any (commandline)) or (FolderPath  has_any (file_path)) or (FolderPath  has_any (commandline)) or ( InitiatingProcessCommandLine has_any (commandline)) or ( InitiatingProcessCommandLine has_any (file_path))
| project TimeGenerated, ActionType, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, RequestAccountName, RequestSourceIP, InitiatingProcessSHA256, FolderPath, Type
| extend timestamp = TimeGenerated, HostCustomEntity = DeviceName , AccountCustomEntity = RequestAccountName, ProcessCustomEntity = InitiatingProcessFileName
),
(DeviceEvents
| where  ( InitiatingProcessCommandLine has_any (file_path)) or ( InitiatingProcessCommandLine has_any (commandline)) or (InitiatingProcessFolderPath has_any (file_path)) or (InitiatingProcessFolderPath has_any (commandline)) or (FolderPath  has_any (file_path)) or (FolderPath has_any (commandline))
| project TimeGenerated, ActionType, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, FolderPath, Type
| extend CommandLine = InitiatingProcessCommandLine
| extend timestamp = TimeGenerated, HostCustomEntity = DeviceName , AccountCustomEntity = InitiatingProcessAccountName, ProcessCustomEntity = InitiatingProcessFileName
),
(SecurityEvent
| where EventID == 4688
| where ( CommandLine has_any (file_path)) or ( CommandLine has_any (commandline))  or (NewProcessName has_any (file_path)) or (NewProcessName has_any (commandline)) or (ParentProcessName has_any (file_path)) or (ParentProcessName has_any (commandline))
| project TimeGenerated, Computer, NewProcessName, ParentProcessName, Account, NewProcessId, Type
| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = Account, ProcessCustomEntity = NewProcessName
)
)
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
    entity_type = Process
    field_mappings {
      identifier = ProcessId
      column_name = ProcessCustomEntity
    }
  }
  tactics = ['Persistence']
  techniques = ['T1546']
  display_name = Zinc Actor IOCs files - October 2022
  description = <<EOT
Identifies a match across filename and commandline IOC's related to an actor tracked by Microsoft as Zinc
EOT
  enabled = True
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
