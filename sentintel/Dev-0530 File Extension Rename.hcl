resource "my_alert_rule" "rule_24" {
  name = "Dev-0530 File Extension Rename"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
(union isfuzzy=true
(DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".h0lyenc" or FolderPath == "C:\\FOR_DECRYPT.html" 
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName), HostCustomEntity = DeviceName, Type, InitiatingProcessId, FileName, FolderPath, EventType = ActionType, Commandline = InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessSHA256, FileHashCustomEntity = SHA256
),
(imFileEvent
| where EventType == "FileCreated" 
| where TargetFilePath endswith ".h0lyenc" or TargetFilePath == "C:\\FOR_DECRYPT.html" 
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by AccountCustomEntity = ActorUsername, HostCustomEntity = DvcHostname, DvcId, Type, EventType,  FileHashCustomEntity = TargetFileSHA256, Hash, TargetFilePath, Commandline = ActingProcessCommandLine
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
    entity_type = FileHash
    field_mappings {
      identifier = Value
      column_name = FileHashCustomEntity
    }
  }
  tactics = ['Impact']
  techniques = ['T1486']
  display_name = Dev-0530 File Extension Rename
  description = <<EOT
Dev-0530 actors are known to encrypt the contents of the victims device as well as renaming the file extensions. This query looks for the creation of files with .h0lyenc extension or presence of ransom note.
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
