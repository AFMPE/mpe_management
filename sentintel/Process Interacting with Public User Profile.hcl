resource "my_alert_rule" "rule_241" {
  name = "Process Interacting with Public User Profile"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT15M
  query_period = PT15M
  severity = Medium
  query = <<EOF
DeviceEvents
| where InitiatingProcessCommandLine contains "C:\\Users\\Public"
| where not (InitiatingProcessFileName has_any ("dcconfigexec.exe", "adobegcclient.exe", "adobe genuine launcher.exe", "gdc.exe", "acrord32.exe", "acslaunch_win-32.exe", "skype.exe", "flexsvr.exe", "s3dhost.exe", "msedge.exe", "rteng7.exe", "icpideditor.exe"))
| where not (InitiatingProcessParentFileName has_any ("acslaunch_win-32.exe"))
| where not (InitiatingProcessFolderPath has_any ("program files (x86)\\common files\\adobe\\adobegcclient", "program files (x86)\\ibm\\client access\\emulator\\pcsws.exe", "ibm\\clientsolutions\\start_programs\\windows_x86-64\\acslaunch_win-64.exe", "ibm\\clientsolutions\\start_programs\\windows_i386-32\\acslaunch_win-32.exe", "program files\\intuit", "Documents\\Autodesk"))
| where not (InitiatingProcessCommandLine has_any ("faxupload.exe", "rdp", ".lnk", "chrome.exe", "Users\\Public\\Desktop\\Mobile Client.lnk", "Users\\Public\\Desktop\\Insight", "wc3270.exe", "Epilog Laser\\_epilog_all_users_\\epilog-create-shortcuts.ps1", "Users\\Public\\Desktop\\Acrobat Reader DC.lnk", "Users\\Public\\UPS\\WSTD", "start-AdSync.ps1", "P1Mobile.exe"))
| where not (FolderPath has_any ("Documents\\Autodesk", "BlockPreviewFolder"))
| extend User = InitiatingProcessAccountName, FileName = InitiatingProcessFileName,  FolderPath = InitiatingProcessFolderPath
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = User
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = DeviceName
    }
    entity_type = File
    field_mappings {
      identifier = Name
      column_name = FileName
    }
  }
  tactics = ['Execution', 'Persistence', 'DefenseEvasion', 'Collection']
  techniques = ['T1547']
  display_name = Process Interacting with Public User Profile
  description = <<EOT
The public user profile is used by threat actors for multiple tactics. Any data being read/written to there should be evaluated for threats.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
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
