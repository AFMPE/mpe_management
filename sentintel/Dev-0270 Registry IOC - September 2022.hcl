resource "my_alert_rule" "rule_325" {
  name = "Dev-0270 Registry IOC - September 2022"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT6H
  query_period = PT6H
  severity = High
  query = <<EOF
(union isfuzzy=true
(SecurityEvent
| where EventID == 4688
| where (CommandLine has_all  ('reg', 'add', 'HKLM\\SOFTWARE\\Policies\\', '/v','/t', 'REG_DWORD', '/d', '/f') and CommandLine has_any('DisableRealtimeMonitoring', 'UseTPMKey', 'UseTPMKeyPIN', 'UseAdvancedStartup', 'EnableBDEWithNoTPM', 'RecoveryKeyMessageSource'))
  or CommandLine has_all ('reg', 'add', 'HKLM\\SOFTWARE\\Policies\\', '/v','/t', 'REG_DWORD', '/d', '/f', 'RecoveryKeyMessage', 'Your drives are Encrypted!', '@')
| project TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account, AccountDomain, ProcessName, ProcessNameFullPath = NewProcessName, EventID, Activity, CommandLine, EventSourceName, Type
),
(DeviceProcessEvents 
| where (InitiatingProcessCommandLine has_all(@'"reg"', 'add', @'"HKLM\SOFTWARE\Policies\', '/v','/t', 'REG_DWORD', '/d', '/f') 
   and InitiatingProcessCommandLine has_any('DisableRealtimeMonitoring', 'UseTPMKey', 'UseTPMKeyPIN', 'UseAdvancedStartup', 'EnableBDEWithNoTPM', 'RecoveryKeyMessageSource') ) 
   or InitiatingProcessCommandLine has_all('"reg"', 'add', @'"HKLM\SOFTWARE\Policies\', '/v','/t', 'REG_DWORD', '/d', '/f', 'RecoveryKeyMessage', 'Your drives are Encrypted!', '@')
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
  tactics = ['Impact']
  techniques = ['T1486']
  display_name = Dev-0270 Registry IOC - September 2022
  description = <<EOT
The query below identifies modification of registry by Dev-0270 actor to disable security feature as well as to add ransom notes
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
