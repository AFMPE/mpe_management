resource "my_alert_rule" "rule_265" {
  name = "Windows Binaries Executed from Non-Default Directory"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
let procList = externaldata(Process:string) [@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Microsoft_Lolbas_Execution_Binaries.csv"] with (format="csv", ignoreFirstRecord=True);
SecurityEvent
| where EventID == 4688 and Process has_any (procList) and not (NewProcessName has_any ("C:\\Windows\\", "C:\\Program Files"))
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by EventID, Computer, SubjectUserName, NewProcessName, Process, CommandLine
| where not ((Process has "bash.exe" and NewProcessName has "cygwin64") or (Process has "forfiles.exe" and NewProcessName has "E:\\oracle\\admin"))
| where not(Process has_any ("Accounting.Application.BE.Explorer.exe"))

EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = SubjectUserName
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = Computer
    }
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = CommandLine
    }
  }
  tactics = ['Execution']
  techniques = ['T1059']
  display_name = Windows Binaries Executed from Non-Default Directory
  description = <<EOT
The query detects Windows binaries, that can be executed from a non-default directory (e.g. C:\Windows\, C:\Windows\System32 etc.). 
Ref: https://lolbas-project.github.io/
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
