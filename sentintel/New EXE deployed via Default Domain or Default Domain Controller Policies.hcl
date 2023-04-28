resource "my_alert_rule" "rule_33" {
  name = "New EXE deployed via Default Domain or Default Domain Controller Policies"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = High
  query = <<EOF
let known_processes = (
  SecurityEvent
  // If adjusting Query Period or Frequency update these
  | where TimeGenerated between(ago(14d)..ago(1d))
  | where EventID == 4688
  | where NewProcessName has_any ("Policies\\{6AC1786C-016F-11D2-945F-00C04fB984F9}", "Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}")
  | summarize by Process);
  SecurityEvent
  // If adjusting Query Period or Frequency update these
  | where TimeGenerated > ago(1d)
  | where EventID == 4688
  | where NewProcessName has_any ("Policies\\{6AC1786C-016F-11D2-945F-00C04fB984F9}", "Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}")
  | where Process !in (known_processes)
  // This will likely apply to multiple hosts so summarize these data
  | summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Process, NewProcessName, CommandLine, Computer
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = Computer
    }
  }
  tactics = ['Execution', 'LateralMovement']
  techniques = ['T1072', 'T1570']
  display_name = New EXE deployed via Default Domain or Default Domain Controller Policies
  description = <<EOT
This detection highlights executables deployed to hosts via either the Default Domain or Default Domain Controller Policies. These policies apply to all hosts or Domain Controllers and best practice is that these policies should not be used for deployment of files.
A threat actor may use these policies to deploy files or scripts to all hosts in a domain.
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
