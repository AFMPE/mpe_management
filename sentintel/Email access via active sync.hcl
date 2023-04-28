resource "my_alert_rule" "rule_362" {
  name = "Email access via active sync"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let timeframe = 1d;
let cmdList = dynamic(["Set-CASMailbox","ActiveSyncAllowedDeviceIDs","add"]);
(union isfuzzy=true
(
SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 4688
| where CommandLine has_all (cmdList)
| project Type, TimeGenerated, Computer, Account, SubjectDomainName, SubjectUserName, Process, ParentProcessName, CommandLine
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer
),
( WindowsEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 4688
| where EventData has_all (cmdList)
| extend CommandLine = tostring(EventData.CommandLine) 
| where CommandLine has_all (cmdList)
| extend Account =  strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend SubjectUserName = tostring(EventData.SubjectUserName)
| extend SubjectDomainName = tostring(EventData.SubjectDomainName)
| extend NewProcessName = tostring(EventData.NewProcessName)
| extend Process=tostring(split(NewProcessName, '\\')[-1])
| extend ParentProcessName = tostring(EventData.ParentProcessName)
| project Type, TimeGenerated, Computer, Account, SubjectDomainName, SubjectUserName, Process, ParentProcessName, CommandLine
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer
),
(
DeviceProcessEvents
| where TimeGenerated >= ago(timeframe)
| where InitiatingProcessCommandLine has_all (cmdList)
| project Type, TimeGenerated, DeviceName, AccountName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName,  InitiatingProcessCommandLine
| extend timestamp = TimeGenerated, AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
),
(
Event
| where TimeGenerated > ago(timeframe)
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EventData = parse_xml(EventData).DataItem.EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key=tostring(['@Name']), Value=['#text']
| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, Type, _ResourceId)
| where TimeGenerated >= ago(timeframe)
| where CommandLine has_all (cmdList)
| extend Type = strcat(Type, ": ", Source)
| project Type, TimeGenerated, Computer, User, Process, ParentImage, CommandLine
| extend timestamp = TimeGenerated, AccountCustomEntity = User, HostCustomEntity = Computer
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
  }
  tactics = ['PrivilegeEscalation']
  techniques = ['T1078', 'T1068']
  display_name = Email access via active sync
  description = <<EOT
This query detects attempts to add attacker devices as allowed IDs for active sync using the Set-CASMailbox command.
This technique was seen in relation to Solorigate attack but the results can indicate potential malicious activity used in different attacks.
- Note that this query can be changed to use the KQL "has_all" operator, which hasn't yet been documented officially, but will be soon.
  In short, "has_all" will only match when the referenced field has all strings in the list.
- Refer to Set-CASMailbox syntax: https://docs.microsoft.com/powershell/module/exchange/set-casmailbox?view=exchange-ps  
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
