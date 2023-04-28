resource "my_alert_rule" "rule_304" {
  name = "DLL Execution via wuauclt.exe"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = High
  query = <<EOF
let SE = (SecurityEvent
    | where Process contains "wuauclt.exe"
    | where not(CommandLine has_any ("UpdateDeploymentProvider.dll"))
    | where CommandLine contains ".dll"
    | extend AccountCustomEntity = Account, HostCustomEntity = Computer
    | project
        TimeGenerated,
        Account,
        Computer,
        CommandLine,
        AccountCustomEntity,
        HostCustomEntity);
let DfE = (DeviceProcessEvents
    | where InitiatingProcessFileName has "wuauclt.exe"
    | where InitiatingProcessCommandLine contains ".dll"
    | where not(InitiatingProcessCommandLine has_any ("UpdateDeploymentProvider.dll", "\\WINDOWS\\SYSTEM32\\UpdateDeploy.dll"))
    | where not(FolderPath has_any ("C:\\Windows\\SoftwareDistribution"))
    | extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
    | project
        TimeGenerated,
        AccountName,
        DeviceName,
        FolderPath,
        ParentProcessCommandLine = InitiatingProcessCommandLine,
        CommandLine = ProcessCommandLine,
        AccountCustomEntity,
        HostCustomEntity
    );
SE
| union DfE
| where not(CommandLine has_any("\\WINDOWS\\SYSTEM32\\UpdateDeploy.dll", "wuaueng.dll", "WerFault.exe"))
| where not(CommandLine contains "UpdateDeploy.dll")
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
  tactics = ['Execution', 'Persistence']
  techniques = ['T1129', 'T1574']
  display_name = DLL Execution via wuauclt.exe
  description = <<EOT
'Technique explained here => //https://dtm.uk/wuauclt/  https://www.joesandbox.com/analysis/215088/0/html'

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
