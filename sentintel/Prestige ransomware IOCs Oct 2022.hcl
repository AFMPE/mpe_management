resource "my_alert_rule" "rule_270" {
  name = "Prestige ransomware IOCs Oct 2022"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
let sha256Hashes = dynamic(["5dd1ca0d471dee41eb3ea0b6ea117810f228354fc3b7b47400a812573d40d91d", "5fc44c7342b84f50f24758e39c8848b2f0991e8817ef5465844f5f2ff6085a57", "6cff0bbd62efe99f381e5cc0c4182b0fb7a9a34e4be9ce68ee6b0d0ea3eee39c"]);
let signames = dynamic(["Ransom:Win32/Prestige"]);
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
//(Event
//| where Source =~ "Microsoft-Windows-Sysmon"
//| where EventID == 1
//| extend EvData = parse_xml(EventData)
//| extend EventDetail = EvData.DataItem.EventData.Data
//| extend Image = EventDetail.[4].["#text"],  CommandLine = EventDetail.[10].["#text"], Hashes = tostring(EventDetail.[17].["#text"])
//| extend Hashes = extract_all(@"(?P<key>\w+)=(?P<value>[a-zA-Z0-9]+)", dynamic(["key","value"]), Hashes)
//| extend Hashes = column_ifexists("Hashes", ""), CommandLine = column_ifexists("CommandLine", "")
//| where (Hashes has_any (sha256Hashes) )  
//| project TimeGenerated, EventDetail, UserName, Computer, Type, Source, Hashes, CommandLine, Image
//| extend Type = strcat(Type, ": ", Source)
//| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = UserName, ProcessCustomEntity = tostring(split(Image, '\\', -1)[-1]), FileHashCustomEntity = Hashes
//),
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
),
(SecurityAlert
| where ProductName == "Microsoft Defender Advanced Threat Protection"
| extend ThreatName = tostring(parse_json(ExtendedProperties).ThreatName)
| where isnotempty(ThreatName)
| where ThreatName has_any (signames)
| extend Computer = tostring(parse_json(Entities)[0].HostName)
| extend timestamp = TimeGenerated, HostCustomEntity = Computer
)
)
EOF
  entity_mapping {
    entity_type = File
    field_mappings {
      identifier = Name
      column_name = FileHashCustomEntity
    }
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
      identifier = HostName
      column_name = HostCustomEntity
    }
  }
  tactics = ['Execution']
  techniques = ['T1203']
  display_name = Prestige ransomware IOCs Oct 2022
  description = <<EOT
This query looks for file hashes and AV signatures associated with Prestige ransomware 
payload.
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
