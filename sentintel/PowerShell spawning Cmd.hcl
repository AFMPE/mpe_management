resource "my_alert_rule" "rule_47" {
  name = "PowerShell spawning Cmd"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Low
  query = <<EOF
let SE = (SecurityEvent 
    | where EventID == 4688
        and ParentProcessName contains "powershell.exe"
        and Process == "cmd.exe" 
    | extend AccountCustomEntity = Account, HostCustomEntity = Computer
    );
let DPE = (DeviceProcessEvents
    | where InitiatingProcessFileName has "powershell.exe" and ProcessCommandLine has "cmd.exe" 
    | extend
        AccountCustomEntity = AccountUpn,
        HostCustomEntity = DeviceName,
        CommandLine = ProcessCommandLine
    );
SE
| union DPE
| where not(CommandLine has_any ("chkdsk", "\\azagent\\A1\\_work\\_temp", "\\Windows\\system32\\sconfig.cmd", "C:\\Program Files\\nodejs\\npm.cmd", "C:\\Program Files\\Azure\\StorageSyncAgent", "uninstall_flash_player.exe", "ProgramData\\chocolatey\\bin\\", "Program Files (x86)\\Microsoft SDKs\\Azure\\", "Microsoft\\AndroidSDK\\25\\tools\\", "\\Program Files\\Microsoft Visual Studio\\2022\\", "Program Files (x86)\\Microsoft Visual Studio\\2019\\", "C:\\WindowsDefenderATPLocalOnboardingScript.cmd", "C:\\nodejs\\npm.cmd", "Packages\\Plugins\\Microsoft.Azure.AzureDefenderForServers.MDE.Windows\\", "dir /A-L /s /r /b", "\\Program Files\\Trend Micro\\", "npm\\ng.cmd", "TOUGHBOOK55BarcodeCOMPORTScript", "\\Lenovo\\VantageService\\", "\\Windows\\ccmcache\\", "\\Windows\\1Lenovo", "\\dev\\AssetHealth", "\\_work\\_code\\assetlens", "\\Program Files (x86)\\Yarn\\bin\\", "ImController.InfInstaller.exe", "GothamFont.cmd", "ArcGIS", "Energy_Azure_Copy.cmd", "AcSELerator Quickset", "IC3Adapter", "Hyland\\OnBase", "AppDeploy Sample Scripts", "Microsoft VS Code", "GuestConfiguration"))| where not(InitiatingProcessCommandLine has_any ("sync-cleardata-win-images-acli.ps1"))
| where CommandLine <> ""
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
  display_name = PowerShell spawning Cmd
  description = <<EOT
'Identifies a suspicious parent child process relationship with cmd.exe descending from PowerShell.exe.'

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
