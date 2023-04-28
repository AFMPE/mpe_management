resource "my_alert_rule" "rule_157" {
  name = "Potential Fodhelper UAC Bypass"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT2H
  query_period = PT2H
  severity = Medium
  query = <<EOF
SecurityEvent
  | where EventID == 4657
  | parse ObjectName with "\\REGISTRY\\" KeyPrefix "\\" RegistryKey
  | project-reorder RegistryKey
  | where RegistryKey has "Software\\Classes\\ms-settings\\shell\\open\\command"
  | extend TimeKey = bin(TimeGenerated, 1h)
  | join (
  SecurityEvent
  | where EventID == 4688
  | where Process =~ "fodhelper.exe"
  | where ParentProcessName endswith "cmd.exe" or ParentProcessName endswith "powershell.exe" or ParentProcessName endswith "powershell_ise.exe"
  | extend TimeKey = bin(TimeGenerated, 1h)) on TimeKey, Computer
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = Computer
    }
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = Account
    }
  }
  tactics = ['PrivilegeEscalation']
  techniques = ['T1548']
  display_name = Potential Fodhelper UAC Bypass
  description = <<EOT
This detection looks for the steps required to conduct a UAC bypass using Fodhelper.exe. By default this detection looks for the setting of the required registry keys and the invoking of the process within 1 hour - this can be tweaked as required.
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
