resource "my_alert_rule" "rule_142" {
  name = "Potential Windows Defender Configuration Change"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
DeviceEvents
| where (InitiatingProcessCommandLine contains "powershell" and InitiatingProcessCommandLine has_any ("Set-MpPreference", "Add-MpPreference"))
    or InitiatingProcessCommandLine contains "WMIC" and InitiatingProcessCommandLine has "MpPreference"
| where not(InitiatingProcessCommandLine has_any ("ETAPS64.exe", "knime.exe"))
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    InitiatingProcessAccountUpn,
    InitiatingProcessCommandLine

EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = InitiatingProcessAccountUpn
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = DeviceName
    }
  }
  tactics = ['DefenseEvasion']
  techniques = ['T1112', 'T1562']
  display_name = Potential Windows Defender Configuration Change
  description = <<EOT
This rule detects commandline/powershell modifications of Windows Defender. This can be used to lower the security settings so that threat actors can run malicious things on the device.
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
