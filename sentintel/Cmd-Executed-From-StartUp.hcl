resource "my_alert_rule" "rule_73" {
  name = "Cmd-Executed-From-StartUp"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
union(SecurityEvent
    | where EventID == "4688"
    | where AccountType == "User"
    | where CommandLine has_any ("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp")
    | extend AccountCustomEntity = Account, HostCustomEntity = Computer),
    (DeviceProcessEvents
    | where ProcessCommandLine has_any ("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp")
    | extend
        AccountCustomEntity = AccountName,
        HostCustomEntity = DeviceName,
        CommandLine = ProcessCommandLine)
| where not(CommandLine has_any ("AECOMBG.bat", "Foray Adams Bridge", "AlternateShellStartup", "Program Files\\Citrix\\", "Program Files (x86)\\Citrix", "Launch.vbs", "CaptureManager_UI.bat", "cognosrcp", "Map Public and Accounting Drive.bat", "Amazon WorkDocs.appref-ms|", "SPARTA Remote Machines.appref-ms|", "AutoHotKey.exe", "EXCEL.exe", "notepad.exe", "seraph_share.cmd", "BGInfoRun.bat", "Infomedia", "eFileCabinet", "RunWallpaperSetup", "BGInfo.cmd", "BGStart.bat", "Microsoft Teams- ATCO.lnk","Microsoft Planner.lnk","Office.lnk", "Microsoft 365.lnk", "Yammer.lnk",  "Messages.lnk", "Outlook (PWA).lnk", "Microsoft Teams.lnk", "Teams.lnk", "Onedrive.lnk"))
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
  techniques = ['T1543']
  display_name = Cmd-Executed-From-StartUp
  description = <<EOT
'Detects if batch script was from StartUp folder, this indicates a batch script was dropped to maintain Persistence as the script will execute upon machine boot.'

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
