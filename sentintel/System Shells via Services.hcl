resource "my_alert_rule" "rule_75" {
  name = "System Shells via Services"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
let SE=(SecurityEvent 
    | where EventID == 4688
        and ParentProcessName has "services.exe"
        and (Process == "cmd.exe" or Process == "powershell.exe") 
    | extend AccountCustomEntity = Account, HostCustomEntity = Computer
    );
let DPE=(DeviceProcessEvents
    | where InitiatingProcessParentFileName has "services.exe"
    | where InitiatingProcessFileName has_any("cmd.exe", "powershell.exe")
    | extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
    );
SE
| union DPE
| where not(ProcessCommandLine has_any("NVDisplay.ContainerLocalSystem", "NvContainerRecoveryNVDisplay.ContainerLocalSystem"))
| where not(InitiatingProcessCommandLine contains "NvContainerRecovery.bat")
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
  techniques = ['T1569']
  display_name = System Shells via Services
  description = <<EOT
'Windows services typically run as SYSTEM and can be used as a privilege escalation opportunity. Malware or penetration testers may run a shell as a service to gain SYSTEM permissions.'

EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
