resource "my_alert_rule" "rule_84" {
  name = "NOBELIUM - Script payload stored in Registry"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let cmdTokens0 = dynamic(['vbscript','jscript']);
let cmdTokens1 = dynamic(['mshtml','RunHTMLApplication']);
let cmdTokens2 = dynamic(['Execute','CreateObject','RegRead','window.close']);
(union isfuzzy=true 
(SecurityEvent
| where TimeGenerated >= ago(14d)
| where EventID == 4688
| where CommandLine has @'\Microsoft\Windows\CurrentVersion'
| where not(CommandLine has_any (@'\Software\Microsoft\Windows\CurrentVersion\Run', @'\Software\Microsoft\Windows\CurrentVersion\RunOnce'))
// If you are receiving false positives, then it may help to make the query more strict by uncommenting one or both of the lines below to refine the matches
//| where CommandLine has_any (cmdTokens0)
//| where CommandLine has_all (cmdTokens1)
| where CommandLine has_all (cmdTokens2)
| project TimeGenerated, Computer, Account, Process, NewProcessName, CommandLine, ParentProcessName, _ResourceId
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account
),
(WindowsEvent
| where TimeGenerated >= ago(14d)
| where EventID == 4688 and EventData has_all(cmdTokens2) and  EventData has @'\Microsoft\Windows\CurrentVersion'
| where not(EventData has_any (@'\Software\Microsoft\Windows\CurrentVersion\Run', @'\Software\Microsoft\Windows\CurrentVersion\RunOnce'))
| extend CommandLine = tostring(EventData.CommandLine)
| where CommandLine has @'\Microsoft\Windows\CurrentVersion'
| where not(CommandLine has_any (@'\Software\Microsoft\Windows\CurrentVersion\Run', @'\Software\Microsoft\Windows\CurrentVersion\RunOnce'))
// If you are receiving false positives, then it may help to make the query more strict by uncommenting one or both of the lines below to refine the matches
//| where CommandLine has_any (cmdTokens0)
//| where CommandLine has_all (cmdTokens1)
| where CommandLine has_all (cmdTokens2)
| extend Account =  strcat(EventData.SubjectDomainName,"\\", EventData.SubjectUserName)
| extend NewProcessName = tostring(EventData.NewProcessName)
| extend Process=tostring(split(NewProcessName, '\\')[-1])
| extend ParentProcessName = tostring(EventData.ParentProcessName)  
| project TimeGenerated, Computer, Account, Process, NewProcessName, CommandLine, ParentProcessName, _ResourceId
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account))
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
  tactics = ['Execution']
  techniques = ['T1059']
  display_name = NOBELIUM - Script payload stored in Registry
  description = <<EOT
This query idenifies when a process execution commandline indicates that a registry value is written to allow for later execution a malicious script
 References: https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
