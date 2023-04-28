resource "my_alert_rule" "rule_61" {
  name = "NOBELIUM - suspicious rundll32.exe execution of vbscript"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
(union isfuzzy=true 
(SecurityEvent
| where EventID == 4688
| where Process =~ 'rundll32.exe' 
| where CommandLine has_all ('Execute','RegRead','window.close')
| project TimeGenerated, Computer, Account, Process, NewProcessName, CommandLine, ParentProcessName, _ResourceId
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account
),
(WindowsEvent
| where EventID == 4688 and EventData has 'rundll32.exe' and EventData has_any ('Execute','RegRead','window.close')
| extend NewProcessName = tostring(EventData.NewProcessName)
| extend Process=tostring(split(NewProcessName, '\\')[-1])
| where Process =~ 'rundll32.exe' 
| extend CommandLine = tostring(EventData.CommandLine)
| where CommandLine has_all ('Execute','RegRead','window.close')
| extend Account =  strcat(EventData.SubjectDomainName,"\\", EventData.SubjectUserName)
| extend ParentProcessName = tostring(EventData.ParentProcessName)  
| project TimeGenerated, Computer, Account, Process, NewProcessName, CommandLine, ParentProcessName, _ResourceId
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account
) )
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
  tactics = ['Persistence']
  techniques = ['T1547']
  display_name = NOBELIUM - suspicious rundll32.exe execution of vbscript
  description = <<EOT
This query idenifies when rundll32.exe executes a specific set of inline VBScript commands
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
