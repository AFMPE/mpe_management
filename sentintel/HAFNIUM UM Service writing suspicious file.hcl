resource "my_alert_rule" "rule_287" {
  name = "HAFNIUM UM Service writing suspicious file"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
let scriptExtensions = dynamic([".php", ".jsp", ".js", ".aspx", ".asmx", ".asax", ".cfm", ".shtml"]);
union isfuzzy=true
(SecurityEvent
| where EventID == 4663
| where Process has_any ("umworkerprocess.exe", "UMService.exe")
| where ObjectName has_any (scriptExtensions)
| where AccessMask in ('0x2','0x100', '0x10', '0x4')
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress
),
  (WindowsEvent
| where EventID == 4663 and EventData has_any ("umworkerprocess.exe", "UMService.exe") and EventData has_any (scriptExtensions) 
| where EventData has_any ('0x2','0x100', '0x10', '0x4')
| extend NewProcessName = tostring(EventData.NewProcessName)
| extend Process=tostring(split(NewProcessName, '\\')[-1])
| where Process has_any ("umworkerprocess.exe", "UMService.exe")
| extend ObjectName = tostring(EventData.ObjectName)
| where ObjectName has_any (scriptExtensions)
| extend AccessMask = tostring(EventData.AccessMask)
| where AccessMask in ('0x2','0x100', '0x10', '0x4')
| extend Account = strcat(EventData.SubjectDomainName,"\\", EventData.SubjectUserName)
| extend IpAddress = tostring(EventData.IpAddress)
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress
),
(imFileEvent
| where EventType == "FileCreated"
| where ActingProcessName has_any ("umworkerprocess.exe", "UMService.exe")
  and
  TargetFileName has_any (scriptExtensions)
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUsername, HostCustomEntity = DvcHostname
),
(DeviceFileEvents
| where ActionType =~ "FileCreated"
| where InitiatingProcessFileName has_any ("umworkerprocess.exe", "UMService.exe")
| where FileName has_any(scriptExtensions)
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingProcessAccountUpn, HostCustomEntity = DeviceName, IPCustomEntity = RequestSourceIP)
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = InitiatingProcessAccountUpn
    }
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
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = DeviceName
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['InitialAccess']
  techniques = ['T1190']
  display_name = HAFNIUM UM Service writing suspicious file
  description = <<EOT
This query looks for the Exchange server UM process writing suspicious files that may be indicative of webshells.
Reference: https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
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
