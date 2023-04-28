resource "my_alert_rule" "rule_35" {
  name = "HAFNIUM New UM Service Child Process"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
let lookback = 14d;
let timeframe = 1d;
(union isfuzzy=true
(SecurityEvent
| where TimeGenerated > ago(lookback) and TimeGenerated < ago(timeframe)
| where EventID == 4688
| where ParentProcessName has_any ("umworkerprocess.exe", "UMService.exe")
| join kind=rightanti (
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where ParentProcessName has_any ("umworkerprocess.exe", "UMService.exe")
| where EventID == 4688) on NewProcessName
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress
),
(WindowsEvent
| where TimeGenerated > ago(lookback) and TimeGenerated < ago(timeframe)
| where EventID == 4688 and EventData has_any ("umworkerprocess.exe", "UMService.exe")
| extend ParentProcessName = tostring(EventData.ParentProcessName)
| where ParentProcessName has_any ("umworkerprocess.exe", "UMService.exe")
| extend NewProcessName = tostring(EventData.NewProcessName)
| extend Account = strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend IpAddress = tostring(EventData.IpAddress)
| join kind=rightanti (
WindowsEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4688  and EventData has_any ("umworkerprocess.exe", "UMService.exe")
| extend ParentProcessName = tostring(EventData.ParentProcessName)
| where ParentProcessName has_any ("umworkerprocess.exe", "UMService.exe")
| extend NewProcessName = tostring(EventData.NewProcessName)
| extend Account = strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend IpAddress = tostring(EventData.IpAddress)) on NewProcessName
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress
))
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
  tactics = ['InitialAccess']
  techniques = ['T1190']
  display_name = HAFNIUM New UM Service Child Process
  description = <<EOT
This query looks for new processes being spawned by the Exchange UM service where that process has not previously been observed before. 
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
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
