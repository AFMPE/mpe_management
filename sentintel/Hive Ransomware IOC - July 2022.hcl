resource "my_alert_rule" "rule_303" {
  name = "Hive Ransomware IOC - July 2022"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT12H
  query_period = PT12H
  severity = High
  query = <<EOF
let iocs = externaldata(DateAdded:string,IoC:string,Type:string,TLP:string) [@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/HiveRansomwareJuly2022.csv"] with (format="csv", ignoreFirstRecord=True);
let sha256Hashes = (iocs | where Type =~ "sha256" | project IoC);
(union isfuzzy=true
(CommonSecurityLog
| where FileHash in (sha256Hashes)
| project TimeGenerated, Message, SourceUserID, FileHash, Type
| extend timestamp = TimeGenerated, FileHashCustomEntity = 'SHA256', Account = SourceUserID
),
//(imFileEvent
//| where TargetFileSHA256 has_any (sha256Hashes)
//| extend Account = ActorUsername, Computer = DvcHostname, IPAddress = SrcIpAddr, CommandLine = ActingProcessCommandLine, FileHash = TargetFileSHA256
//| project Type, TimeGenerated, Computer, Account, IPAddress, CommandLine, FileHash
//),
(Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| extend Image = EventDetail.[4].["#text"],  CommandLine = EventDetail.[10].["#text"], Hashes = tostring(EventDetail.[17].["#text"])
| extend Hashes = extract_all(@"(?P<key>\w+)=(?P<value>[a-zA-Z0-9]+)", dynamic(["key","value"]), Hashes)
| extend Hashes = column_ifexists("Hashes", ""), CommandLine = column_ifexists("CommandLine", "")
| where (Hashes has_any (sha256Hashes) )  
| project TimeGenerated, EventDetail, UserName, Computer, Type, Source, Hashes, CommandLine, Image
| extend Type = strcat(Type, ": ", Source)
| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = UserName, ProcessCustomEntity = tostring(split(Image, '\\', -1)[-1]), FileHashCustomEntity = Hashes
),
(DeviceEvents
| where InitiatingProcessSHA256 has_any (sha256Hashes) or SHA256 has_any (sha256Hashes)
| project TimeGenerated, ActionType, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessSHA256, Type
| extend timestamp = TimeGenerated, HostCustomEntity = DeviceName , AccountCustomEntity = InitiatingProcessAccountName, ProcessCustomEntity = InitiatingProcessFileName, AlgorithmCustomEntity = "SHA256", FileHashCustomEntity = InitiatingProcessSHA256,  CommandLine = InitiatingProcessCommandLine,Image = InitiatingProcessFolderPath
),
(DeviceFileEvents
| where SHA256 has_any (sha256Hashes)
| project TimeGenerated, ActionType, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessSHA256, Type
| extend timestamp = TimeGenerated, HostCustomEntity = DeviceName , AccountCustomEntity = InitiatingProcessAccountName, ProcessCustomEntity = InitiatingProcessFileName, AlgorithmCustomEntity = "SHA256", FileHashCustomEntity = InitiatingProcessSHA256,  CommandLine = InitiatingProcessCommandLine,Image = InitiatingProcessFolderPath
),
(DeviceImageLoadEvents
| where SHA256 has_any (sha256Hashes)
| project TimeGenerated, ActionType, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessSHA256, Type
| extend timestamp = TimeGenerated, HostCustomEntity = DeviceName , AccountCustomEntity = InitiatingProcessAccountName, ProcessCustomEntity = InitiatingProcessFileName, AlgorithmCustomEntity = "SHA256", FileHashCustomEntity = InitiatingProcessSHA256,  CommandLine = InitiatingProcessCommandLine,Image = InitiatingProcessFolderPath
)
)
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = Process
    field_mappings {
      identifier = ProcessId
      column_name = ProcessCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = ['T1486']
  display_name = Hive Ransomware IOC - July 2022
  description = <<EOT
Identifies a hash match related to Hive Ransomware across various data sources.
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
