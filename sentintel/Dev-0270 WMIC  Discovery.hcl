resource "my_alert_rule" "rule_25" {
  name = "Dev-0270 WMIC  Discovery"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT6H
  query_period = PT6H
  severity = High
  query = <<EOF
(union isfuzzy=true
(SecurityEvent
| where EventID==4688
| where CommandLine has "wmic computersystem get domain" and ParentProcessName =~ "dllhost.exe"
| project TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account, AccountDomain, ProcessName, ProcessNameFullPath = NewProcessName, EventID, Activity, CommandLine, EventSourceName, Type
),
(DeviceProcessEvents 
| where InitiatingProcessFileName =~ "dllhost.exe" and InitiatingProcessCommandLine == "dllhost.exe" 
| where ProcessCommandLine has "wmic computersystem get domain" 
| extend timestamp = TimeGenerated, AccountCustomEntity =  InitiatingProcessAccountName, HostCustomEntity = DeviceName
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
  tactics = ['Discovery']
  techniques = ['T1482']
  display_name = Dev-0270 WMIC  Discovery
  description = <<EOT
The query below identifies dllhost.exe using WMIC to discover additional hosts and associated domains in the environment.
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
