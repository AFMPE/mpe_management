resource "my_alert_rule" "rule_36" {
  name = "PE file dropped in Color Profile Folder"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
DeviceFileEvents
  | where ActionType =~ "FileCreated"
  | where FolderPath has "C:\\Windows\\System32\\spool\\drivers\\color\\" 
  | where FileName endswith ".exe" or FileName endswith ".dll"
EOF
  entity_mapping {
    entity_type = File
    field_mappings {
      identifier = Name
      column_name = FileName
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = DeviceName
    }
  }
  tactics = ['Execution']
  techniques = ['T1203']
  display_name = PE file dropped in Color Profile Folder
  description = <<EOT
This query looks for writes of PE files to C:\Windows\System32\spool\drivers\color\.
  This is a common directory used by malware, as well as some legitimate programs, and writes of PE files to the folder should be monitored.
  Ref: https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/
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
