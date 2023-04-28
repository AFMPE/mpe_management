resource "my_alert_rule" "rule_314" {
  name = "Zinc Actor IOCs domains hashes IPs and useragent - October 2022"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT6H
  query_period = PT6H
  severity = High
  query = <<EOF
let iocs = externaldata(DateAdded:string,IoC:string,Type:string) [@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/ZincOctober2022IOCs.csv"] with (format="csv", ignoreFirstRecord=True);
let domains = (iocs | where Type =~ "domainname"| project IoC);
let IPList = (iocs | where Type =~ "ip"| project IoC);
let sha256Hashes = (iocs | where Type =~ "sha256" | project IoC);
let useragents = (iocs | where Type =~ "useragent" | project IoC);
(union isfuzzy=true
(CommonSecurityLog
| where DestinationHostName has_any (domains) or RequestURL has_any (domains) or Message has_any (domains)
or  SourceIP has_any (IPList) or DestinationIP  has_any (IPList)
| parse Message with * '(' DNSName ')' *
| project TimeGenerated, Message, SourceUserID, RequestURL, DestinationHostName, Type, SourceIP, DestinationIP, DNSName
| extend timestamp = TimeGenerated, AccountCustomEntity = SourceUserID, UrlCustomEntity = RequestURL , IPCustomEntity = DestinationIP, DNSCustomEntity = DNSName
),
(DnsEvents
| where Name in~ (domains) or IPAddresses has_any (IPList)
| project TimeGenerated, Computer, IPAddresses, Name, ClientIP, Type
| extend DNSName = Name, Host = Computer
| extend timestamp = TimeGenerated, HostCustomEntity = Host, DNSCustomEntity = DNSName, IPCustomEntity = IPAddresses
),
(VMConnection
| where  RemoteDnsCanonicalNames has_any (domains)  or  SourceIp has_any (IPList) or DestinationIp has_any (IPList)
| parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
| project TimeGenerated, Computer, Direction, RemoteDnsCanonicalNames, ProcessName, SourceIp, DestinationIp, DestinationPort, DNSName,BytesSent, BytesReceived, RemoteCountry, Type
| extend timestamp = TimeGenerated, IPCustomEntity = DestinationIp, HostCustomEntity = Computer, ProcessCustomEntity = ProcessName, DNSCustomEntity = DNSName
),
(Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 3
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| extend SourceIP = tostring(EventDetail.[9].["#text"]), DestinationIP = tostring(EventDetail.[14].["#text"]), Image = EventDetail.[4].["#text"]
| where  SourceIP has_any (IPList) or DestinationIP has_any (IPList)
| project TimeGenerated, SourceIP, DestinationIP, Image, UserName, Computer, EventDetail, Type
| extend timestamp = TimeGenerated, AccountCustomEntity = UserName, ProcessCustomEntity = tostring(split(Image, '\\', -1)[-1]), HostCustomEntity = Computer , IPCustomEntity = DestinationIP
),  
(DeviceNetworkEvents
| where RemoteUrl has_any (domains) or RemoteIP has_any (IPList) or InitiatingProcessSHA256 in (sha256Hashes) 
| project TimeGenerated, ActionType, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, RemoteIP, RemoteUrl, LocalIP, Type
| extend timestamp = TimeGenerated, IPCustomEntity = RemoteIP, HostCustomEntity = DeviceName, UrlCustomEntity =RemoteUrl
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallDnsProxy"
| project TimeGenerated,Resource, msg_s, Type
| parse msg_s with "DNS Request: " ClientIP ":" ClientPort " - " QueryID " " Request_Type " " Request_Class " " Request_Name ". " Request_Protocol " " Request_Size " " EDNSO_DO " " EDNS0_Buffersize " " Responce_Code " " Responce_Flags " " Responce_Size " " Response_Duration
| where Request_Name has_any (domains) or ClientIP has_any (IPList)
| extend timestamp = TimeGenerated, DNSName = Request_Name, IPCustomEntity = ClientIP
),
(AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallApplicationRule"
| project TimeGenerated,Resource, msg_s
| parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
| where DestinationHost has_any (domains) or SourceHost has_any (IPList)
| extend timestamp = TimeGenerated, DNSName = DestinationHost, IPCustomEntity = SourceHost
),
(Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| parse EventDetail with * 'SHA256=' SHA256 '",' *
| extend Image = EventDetail.[4].["#text"],  CommandLine = EventDetail.[10].["#text"]
| where SHA256 has_any (sha256Hashes)
| project TimeGenerated, EventDetail, UserName, Computer, Type, Source, SHA256, CommandLine, Image
| extend Type = strcat(Type, ": ", Source)
| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = UserName, ProcessCustomEntity = tostring(split(Image, '\\', -1)[-1]), AlgorithmCustomEntity = "SHA256", FileHashCustomEntity = SHA256
),  
(DeviceProcessEvents
| where  InitiatingProcessSHA256 has_any (sha256Hashes)
| project TimeGenerated, ActionType, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessSHA256, FolderPath, Type
| extend timestamp = TimeGenerated, HostCustomEntity = DeviceName , AccountCustomEntity = InitiatingProcessAccountName, ProcessCustomEntity = InitiatingProcessFileName, AlgorithmCustomEntity = "SHA256", FileHashCustomEntity = InitiatingProcessSHA256
),
(DeviceFileEvents
| where  InitiatingProcessSHA256 has_any (sha256Hashes)
| project TimeGenerated, ActionType, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, RequestAccountName, RequestSourceIP, InitiatingProcessSHA256, FolderPath, Type
| extend timestamp = TimeGenerated, HostCustomEntity = DeviceName , AccountCustomEntity = RequestAccountName, ProcessCustomEntity = InitiatingProcessFileName, AlgorithmCustomEntity = "SHA256", FileHashCustomEntity = InitiatingProcessSHA256
),
(DeviceEvents
| where  InitiatingProcessSHA256 has_any (sha256Hashes)
| project TimeGenerated, ActionType, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessSHA256, FolderPath, Type
| extend CommandLine = InitiatingProcessCommandLine
| extend timestamp = TimeGenerated, HostCustomEntity = DeviceName , AccountCustomEntity = InitiatingProcessAccountName, ProcessCustomEntity = InitiatingProcessFileName, AlgorithmCustomEntity = "SHA256", FileHashCustomEntity = InitiatingProcessSHA256
),
(OfficeActivity
| where ClientIP has_any (IPList) or UserAgent has_any (useragents)
| project TimeGenerated, UserAgent, Operation, RecordType, UserId, ClientIP, Type
| extend timestamp = TimeGenerated, IPCustomEntity = ClientIP, AccountCustomEntity = UserId
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
    entity_type = FileHash
    field_mappings {
      identifier = Algorithm
      column_name = AlgorithmCustomEntity
      identifier = Value
      column_name = FileHashCustomEntity
    }
  }
  tactics = ['Persistence']
  techniques = ['T1546']
  display_name = Zinc Actor IOCs domains hashes IPs and useragent - October 2022
  description = <<EOT
Identifies a match across domainname, IP, hash and useragent IOCs related to an actor tracked by Microsoft as Zinc
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
