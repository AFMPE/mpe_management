resource "my_alert_rule" "rule_281" {
  name = "ACTINIUM Actor IOCs - Feb 2022"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT6H
  query_period = PT6H
  severity = High
  query = <<EOF
let iocs = externaldata(DateAdded:string,IoC:string,Type:string) [@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/ActiniumIOC.csv"] with (format="csv", ignoreFirstRecord=True);
let domains = (iocs | where Type =~ "domainname"| project IoC);
let sha256Hashes = (iocs | where Type =~ "sha256" | project IoC);
(union isfuzzy=true
(DeviceProcessEvents
| where InitiatingProcessSHA256 in (sha256Hashes) or SHA256 in (sha256Hashes) or  (ProcessCommandLine has ('schtasks.exe /CREATE /sc minute /mo 12 /tn')  and ProcessCommandLine has ('/tr "wscript.exe') and ProcessCommandLine has ('"%PUBLIC%\\Pictures\\') and ProcessCommandLine has ('//e:VBScript //b" /F')) or (ProcessCommandLine has ('wscript.exe C:\\Users\\') and ProcessCommandLine has ('.wav') and  ProcessCommandLine has ('//e:VBScript //b'))
| project TimeGenerated, ActionType, DeviceId, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCommandLine, FolderPath, InitiatingProcessFolderPath, ProcessId, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName,  InitiatingProcessSHA256, Type, AccountName, SHA256, FileName
| extend Account = AccountName, Computer = DeviceName,  FileHash = case(InitiatingProcessSHA256 in (sha256Hashes), "InitiatingProcessSHA256", SHA256 in (sha256Hashes), "SHA256", "No Match")
| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = Account, ProcessCustomEntity = FileName, FileHashCustomEntity = case(FileHash == "InitiatingProcessSHA256", InitiatingProcessSHA256, FileHash == "SHA256", SHA256, "No Match")
),
( SecurityEvent
| where EventID == 4688
| where (CommandLine has ('schtasks.exe /CREATE /sc minute /mo 12 /tn')  and CommandLine has ('/tr "wscript.exe') and CommandLine has ('"%PUBLIC%\\Pictures\\') and CommandLine has ('//e:VBScript //b" /F')) or (CommandLine has ('wscript.exe C:\\Users\\') and CommandLine has ('.wav') and  CommandLine has ('//e:VBScript //b'))
| project TimeGenerated, Computer, NewProcessName, ParentProcessName, Account, NewProcessId, Type, EventID
| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = Account, ProcessCustomEntity = NewProcessName
),
( CommonSecurityLog
| where FileHash in (sha256Hashes)
| project TimeGenerated, Message, SourceUserID, FileHash, Type
| extend timestamp = TimeGenerated, FileHashCustomEntity = 'SHA256', Account = SourceUserID
),
( imFileEvent
| where Hash in~ (sha256Hashes) or  (ActingProcessCommandLine  has ('schtasks.exe /CREATE /sc minute /mo 12 /tn')  and ActingProcessCommandLine  has ('/tr "wscript.exe') and ActingProcessCommandLine  has ('"%PUBLIC%\\Pictures\\') and ActingProcessCommandLine  has ('//e:VBScript //b" /F')) or (ActingProcessCommandLine  has ('wscript.exe C:\\Users\\') and ActingProcessCommandLine  has ('.wav') and  ActingProcessCommandLine  has ('//e:VBScript //b'))
| extend Account = ActorUsername, Computer = DvcHostname, IPAddress = SrcIpAddr, CommandLine = ActingProcessCommandLine, FileHash = Hash
| project Type, TimeGenerated, Computer, Account, IPAddress, CommandLine, FileHash
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer
),
(Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| extend Image = EventDetail.[4].["#text"],  CommandLine = EventDetail.[10].["#text"], Hashes = tostring(EventDetail.[17].["#text"])
| extend Hashes = extract_all(@"(?P<key>\w+)=(?P<value>[a-zA-Z0-9]+)", dynamic(["key","value"]), Hashes)
| extend Hashes = column_ifexists("Hashes", ""), CommandLine = column_ifexists("CommandLine", "")
| where (Hashes has_any (sha256Hashes) ) or (CommandLine has ('schtasks.exe /CREATE /sc minute /mo 12 /tn')  and CommandLine has ('/tr "wscript.exe') and CommandLine has ('"%PUBLIC%\\Pictures\\') and CommandLine has ('//e:VBScript //b" /F')) or (CommandLine has ('wscript.exe C:\\Users\\') and CommandLine has ('.wav') and  CommandLine has ('//e:VBScript //b'))
| project TimeGenerated, EventDetail, UserName, Computer, Type, Source, Hashes, CommandLine, Image
| extend Type = strcat(Type, ": ", Source)
| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = UserName, ProcessCustomEntity = tostring(split(Image, '\\', -1)[-1]), FileHashCustomEntity = Hashes
),
(DnsEvents
| where Name in~ (domains)  
| project TimeGenerated, Computer, IPAddresses, Name, ClientIP, Type
| extend DestinationIPAddress = IPAddresses, DNSName = Name, Computer 
| extend timestamp = TimeGenerated, IPCustomEntity = DestinationIPAddress
),
(VMConnection
| where RemoteDnsCanonicalNames has_any (domains)
| parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
| project TimeGenerated, Computer, Direction, ProcessName, SourceIp, DestinationIp, DestinationPort, RemoteDnsQuestions, DNSName,BytesSent, BytesReceived, RemoteCountry, Type
| extend timestamp = TimeGenerated, IPCustomEntity = DestinationIp, File = ProcessName
),
(AzureDiagnostics 
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallApplicationRule"
| project TimeGenerated,Resource, msg_s, Type
| parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
| where isnotempty(DestinationHost)
| where DestinationHost has_any (domains)  
| extend timestamp = TimeGenerated, DNSName = DestinationHost, IPCustomEntity = SourceHost
),
(DeviceNetworkEvents 
| where isnotempty(RemoteUrl) 
| where RemoteUrl  in~ (domains)  
| project Type, TimeGenerated, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessAccountName
| extend timestamp = TimeGenerated, HostCustomEntity = DeviceName , AccountCustomEntity = InitiatingProcessAccountName, DNSName = RemoteUrl, IPCustomEntity = RemoteIP
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
  techniques = ['T1098']
  display_name = ACTINIUM Actor IOCs - Feb 2022
  description = <<EOT
Identifies a match across various data feeds for domains, hashes and commands related to an actor tracked by Microsoft as Actinium.
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
