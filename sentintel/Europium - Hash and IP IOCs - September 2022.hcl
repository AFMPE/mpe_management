resource "my_alert_rule" "rule_257" {
  name = "Europium - Hash and IP IOCs - September 2022"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT12H
  query_period = PT12H
  severity = High
  query = <<EOF
let iocs = externaldata(DateAdded: string, IoC: string, Type: string, TLP: string) [@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Europium_September2022.csv"] with (format="csv", ignoreFirstRecord=True);
let sha256Hashes = (iocs
    | where Type =~ "sha256"
    | project IoC);
let IPList = (iocs
    | where Type =~ "ip"
    | project IoC);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
(union isfuzzy=true
    (CommonSecurityLog
    | where SourceIP in (IPList) or DestinationIP in (IPList) or Message has_any (IPList)
    | parse Message with * '(' DNSName ')' * 
    | project
        TimeGenerated,
        SourceIP,
        DestinationIP,
        Message,
        SourceUserID,
        RequestURL,
        DNSName,
        Type
    | extend
        MessageIP = extract(IPRegex, 0, Message),
        RequestIP = extract(IPRegex, 0, RequestURL)
    | extend IPMatch = case(SourceIP in (IPList), "SourceIP", DestinationIP in (IPList), "DestinationIP", MessageIP in (IPList), "Message", "NoMatch")
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, IPMatch == "Message", MessageIP, "NoMatch"),
        AccountCustomEntity = SourceUserID
    ),
    (DnsEvents
    | where IPAddresses in (IPList)  
    | project TimeGenerated, Computer, IPAddresses, Name, ClientIP, Type
    | extend DestinationIPAddress = IPAddresses, DNSName = Name, Computer 
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = DestinationIPAddress,
        HostCustomEntity = Computer
    ),
    (VMConnection
    | where SourceIp in (IPList) or DestinationIp in (IPList)
    | parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
    | project
        TimeGenerated,
        Computer,
        Direction,
        ProcessName,
        SourceIp,
        DestinationIp,
        DestinationPort,
        RemoteDnsQuestions,
        DNSName,
        BytesSent,
        BytesReceived,
        RemoteCountry,
        Type
    | extend IPMatch = case(SourceIp in (IPList), "SourceIP", DestinationIp in (IPList), "DestinationIP", "None") 
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = case(IPMatch == "SourceIP", SourceIp, IPMatch == "DestinationIP", DestinationIp, "NoMatch"),
        File = ProcessName,
        HostCustomEntity = Computer
    ),
    (Event
    | where Source == "Microsoft-Windows-Sysmon"
    | where EventID == 3
    | extend EvData = parse_xml(EventData)
    | extend EventDetail = EvData.DataItem.EventData.Data
    | extend
        SourceIP = tostring(EventDetail.[9].["#text"]),
        DestinationIP = tostring(EventDetail.[14].["#text"]),
        Image = tostring(EventDetail.[4].["#text"])
    | where SourceIP in (IPList) or DestinationIP in (IPList)
    | project TimeGenerated, SourceIP, DestinationIP, Image, UserName, Computer, Type
    | extend IPMatch = case(SourceIP in (IPList), "SourceIP", DestinationIP in (IPList), "DestinationIP", "None")
    | extend
        timestamp = TimeGenerated,
        File = tostring(split(Image, '\\', -1)[-1]),
        IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, "None"),
        HostCustomEntity = Computer,
        AccountCustomEntity = UserName
    ), 
    (OfficeActivity
    | where ClientIP in (IPList) 
    | project TimeGenerated, UserAgent, Operation, RecordType, UserId, ClientIP, Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = ClientIP,
        AccountCustomEntity = UserId
    ),
    (DeviceNetworkEvents
    | where RemoteIP in (IPList) or InitiatingProcessSHA256 in (sha256Hashes)
    | project
        TimeGenerated,
        ActionType,
        DeviceId,
        Computer = DeviceName,
        InitiatingProcessAccountDomain,
        InitiatingProcessAccountName,
        InitiatingProcessCommandLine,
        InitiatingProcessFolderPath,
        InitiatingProcessId,
        InitiatingProcessParentFileName,
        InitiatingProcessFileName,
        RemoteIP,
        RemoteUrl,
        RemotePort,
        LocalIP,
        Type
    | extend
        timestamp = TimeGenerated,
        IPCustomEntity = RemoteIP,
        HostCustomEntity = Computer,
        AccountCustomEntity = InitiatingProcessAccountName
    ),
    (WindowsFirewall
    | where SourceIP in (IPList) or DestinationIP in (IPList) 
    | project
        TimeGenerated,
        Computer,
        CommunicationDirection,
        SourceIP,
        DestinationIP,
        SourcePort,
        DestinationPort,
        Type
    | extend IPMatch = case(SourceIP in (IPList), "SourceIP", DestinationIP in (IPList), "DestinationIP", "None")
    | extend
        timestamp = TimeGenerated,
        HostCustomEntity = Computer,
        IPCustomEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, "None")
    ), 
    //(imFileEvent
    //| where TargetFileSHA256 has_any (sha256Hashes)
    //| extend Account = ActorUsername, Computer = DvcHostname, IPAddress = SrcIpAddr, CommandLine = ActingProcessCommandLine, FileHash = TargetFileSHA256
    //| project Type, TimeGenerated, Computer, Account, IPAddress, CommandLine, FileHash
    //| extend timestamp = TimeGenerated, IPCustomEntity = IPAddress,  HostCustomEntity = Computer, AccountCustomEntity = Account, AlgorithmCustomEntity = "SHA256", FileHashCustomEntity = FileHash
    //),
    (DeviceFileEvents
    | where SHA256 has_any (sha256Hashes)
    | extend
        timestamp = TimeGenerated,
        HostCustomEntity = DeviceName,
        AccountCustomEntity = InitiatingProcessAccountName,
        AlgorithmCustomEntity = "SHA256",
        FileHashCustomEntity = InitiatingProcessSHA256,
        CommandLine = InitiatingProcessCommandLine,
        Image = InitiatingProcessFolderPath
    ),
    (DeviceImageLoadEvents
    | where SHA256 has_any (sha256Hashes)
    | project
        TimeGenerated,
        ActionType,
        DeviceId,
        DeviceName,
        InitiatingProcessAccountDomain,
        InitiatingProcessAccountName,
        InitiatingProcessCommandLine,
        InitiatingProcessFolderPath,
        InitiatingProcessId,
        InitiatingProcessParentFileName,
        InitiatingProcessFileName,
        InitiatingProcessSHA256,
        Type
    | extend
        timestamp = TimeGenerated,
        HostCustomEntity = DeviceName,
        AccountCustomEntity = InitiatingProcessAccountName,
        AlgorithmCustomEntity = "SHA256",
        FileHashCustomEntity = InitiatingProcessSHA256,
        CommandLine = InitiatingProcessCommandLine,
        Image = InitiatingProcessFolderPath
    ),
    (Event
    | where Source =~ "Microsoft-Windows-Sysmon"
    | where EventID == 1
    | extend EvData = parse_xml(EventData)
    | extend EventDetail = EvData.DataItem.EventData.Data
    | extend
        Image = EventDetail.[4].["#text"],
        CommandLine = EventDetail.[10].["#text"],
        Hashes = tostring(EventDetail.[17].["#text"])
    | extend Hashes = extract_all(@"(?P<key>\w+)=(?P<value>[a-zA-Z0-9]+)", dynamic(["key", "value"]), Hashes)
    | extend
        Hashes = column_ifexists("Hashes", ""),
        CommandLine = column_ifexists("CommandLine", "")
    | where (Hashes has_any (sha256Hashes))  
    | project
        TimeGenerated,
        EventDetail,
        UserName,
        Computer,
        Type,
        Source,
        Hashes,
        CommandLine,
        Image
    | extend Type = strcat(Type, ": ", Source)
    | extend
        timestamp = TimeGenerated,
        HostCustomEntity = Computer,
        AccountCustomEntity = UserName,
        FileHashCustomEntity = Hashes
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
  }
  tactics = ['CommandAndControl', 'CredentialAccess']
  techniques = ['T1071', 'T1003']
  display_name = Europium - Hash and IP IOCs - September 2022
  description = <<EOT
Identifies a match across various data feeds for  hashes and IP IOC related to Europium
 Reference: https://www.microsoft.com/security/blog/2022/09/08/microsoft-investigates-iranian-attacks-against-the-albanian-government
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
