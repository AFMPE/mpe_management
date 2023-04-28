resource "my_alert_rule" "rule_93" {
  name = "Malicious Chrome Extension Detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT15M
  query_period = PT15M
  severity = High
  query = <<EOF
DeviceFileEvents
| where FolderPath has_any ("mmnbenehknklpbendgmgngeaignppnbe", "flijfnhifgdcbhglkneplegafminjnhn", "adikhbfjdbjkhelbdnffogkobkekkkej", "pojgkmkfincpdkdgjepkmdekcahmckjp", "gbnahglfafmhaehbdmjedfhdmimjcbed")
| project TimeGenerated, DeviceName, UserName = InitiatingProcessAccountName, FolderPath
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = UserName
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = DeviceName
    }
  }
  tactics = ['Execution', 'Persistence']
  techniques = ['T1204']
  display_name = Malicious Chrome Extension Detected
  description = <<EOT
Detects the installation of the extensions listed here: https://securityaffairs.co/wordpress/135091/hacking/malicious-google-chrome-extensions.html
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
