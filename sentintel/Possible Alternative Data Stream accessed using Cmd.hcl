resource "my_alert_rule" "rule_256" {
  name = "Possible Alternative Data Stream accessed using Cmd"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Low
  query = <<EOF
union(DeviceProcessEvents
| where ProcessCommandLine has "cmd.exe" and (ProcessCommandLine matches regex @"[.]\w\w\w[:]" or ProcessCommandLine matches regex @"[.]\w\w\w[:][:]")
| extend AccountCustomEntity = AccountName, CommandLine = ProcessCommandLine, HostCustomEntity = DeviceName
),
(
SecurityEvent
| where EventID == "4688"
| where CommandLine has "cmd.exe" and (CommandLine matches regex @"[.]\w\w\w[:]" or CommandLine matches regex @"[.]\w\w\w[:][:]")
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
)
| where not (CommandLine has_any ("dsa_control.cmd", "start chrome", "start iexplore", "start firefox", "start msedge", "OpenSSL.exe"))
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
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = CommandLine
    }
  }
  tactics = ['Execution']
  techniques = ['T1059']
  display_name = Possible Alternative Data Stream accessed using Cmd
  description = <<EOT
Alternative Data Streams allow files to contain more than one stream of data. Windows Explorer doesn’t provide a way of seing what alternate data streams are in a file (or a way to remove them without deleting the file) but they can be created and accessed easily. Because they are difficult to find they are often used by hackers to hide files on machines that they’ve compromised (perhaps files for a rootkit). Executables in alternate data streams can be executed from the command line but they will not show up in Windows Explorer.

Ref: https://owasp.org/www-community/attacks/Windows_alternate_data_stream
Ref: https://lolbas-project.github.io/lolbas/Binaries/Cmd/
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
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
