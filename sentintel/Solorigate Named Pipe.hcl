resource "my_alert_rule" "rule_194" {
  name = "Solorigate Named Pipe"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
(union isfuzzy=true
(Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID in (17,18)
| where EventData has '583da945-62af-10e8-4902-a8f205c72b2e'
| extend EventData = parse_xml(EventData).DataItem.EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key = tostring(column_ifexists('@Name', "")), Value = column_ifexists('#text', "")
| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, MG, ManagementGroupName, _ResourceId)
| extend PipeName = column_ifexists("PipeName", "")
| extend Account = UserName
),
(
SecurityEvent
| where EventID == '5145'
// %%4418 looks for presence of CreatePipeInstance value 
| where AccessList has '%%4418'     
| where RelativeTargetName has '583da945-62af-10e8-4902-a8f205c72b2e'
),
(
WindowsEvent
| where EventID == '5145' and EventData has '%%4418'  and EventData has '583da945-62af-10e8-4902-a8f205c72b2e' 
// %%4418 looks for presence of CreatePipeInstance value 
| extend AccessList= tostring(EventData.AccessList)
| where AccessList has '%%4418'     
| extend RelativeTargetName= tostring(EventData.RelativeTargetName)
| where RelativeTargetName has '583da945-62af-10e8-4902-a8f205c72b2e'
| extend Account =  strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
)
)
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer
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
  tactics = ['DefenseEvasion', 'PrivilegeEscalation']
  techniques = ['T1055']
  display_name = Solorigate Named Pipe
  description = <<EOT
Identifies a match across various data feeds for named pipe IOCs related to the Solorigate incident.
 For the sysmon events required for this detection, logging for Named Pipe Events needs to be configured in Sysmon config (Event ID 17 and Event ID 18)
 Reference: https://techcommunity.microsoft.com/t5/azure-sentinel/solarwinds-post-compromise-hunting-with-azure-sentinel/ba-p/1995095
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
