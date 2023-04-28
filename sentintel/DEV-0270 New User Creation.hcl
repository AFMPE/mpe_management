resource "my_alert_rule" "rule_327" {
  name = "DEV-0270 New User Creation"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT6H
  query_period = PT6H
  severity = High
  query = <<EOF
(union isfuzzy=true
(SecurityEvent
| where EventID == 4688
| where CommandLine has_all ('net user', '/add') 
| parse CommandLine with * "user " username " "*
| extend password = extract(@"\buser\s+[^\s]+\s+([^\s]+)", 1, CommandLine) 
| where username in('DefaultAccount') or password in('P@ssw0rd1234', '_AS_@1394') 
| project TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account, AccountDomain, ProcessName, ProcessNameFullPath = NewProcessName, EventID, Activity, CommandLine, EventSourceName, Type
),
(DeviceProcessEvents 
| where InitiatingProcessCommandLine has_all('net user', '/add') 
| parse InitiatingProcessCommandLine with * "user " username " "* 
| extend password = extract(@"\buser\s+[^\s]+\s+([^\s]+)", 1, InitiatingProcessCommandLine) 
| where username in('DefaultAccount') or password in('P@ssw0rd1234', '_AS_@1394') 
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
  tactics = ['Persistence']
  techniques = ['T1098']
  display_name = DEV-0270 New User Creation
  description = <<EOT
The following query tries to detect creation of a new user using a known DEV-0270 username/password schema
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
